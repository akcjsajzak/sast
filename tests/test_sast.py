"""End-to-end and unit tests for the SAST engine (stdlib unittest)."""
from __future__ import annotations

import io
import json
import os
import tempfile
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
            '$apiKey = "sk_live_AbCdEf123456";': "php-hardcoded-secret",
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


if __name__ == "__main__":
    unittest.main()
