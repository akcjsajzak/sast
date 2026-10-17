"""End-to-end and unit tests for the SAST engine (stdlib unittest)."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from sast.advisory.db import AdvisoryDB
from sast.advisory.importers import import_feed
from sast.advisory.semver import satisfies
from sast.detection.framework import detect_framework
from sast.detection.language import detect_language
from sast.engine import ScanEngine, ScanOptions
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


if __name__ == "__main__":
    unittest.main()
