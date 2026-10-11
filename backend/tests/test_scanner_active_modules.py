from app.scanner.crawler import CrawlResult, crawl_target
from app.scanner.http_client import SafeHttpClient
from app.scanner.modules import exposed_files, sqli, xss


def _client():
    return SafeHttpClient(allow_local=True, timeout_seconds=2)


def test_exposed_files_finds_real_demo_files_and_masks_sample(demo_target_url):
    result = exposed_files.run(demo_target_url, _client(), depth="standard")

    findings = {finding["affected_url"].rsplit("/", 1)[-1]: finding for finding in result["findings"]}
    env_finding = next(finding for finding in result["findings"] if "/.env" in finding["affected_url"])
    full_fake_env = "DEMO_MODE=true\nFAKE_API_KEY=not-a-real-secret\nFAKE_DB_PASSWORD=example-only\n"
    assert env_finding["severity"] == "critical"
    assert "Path: /.env" in env_finding["evidence"]
    assert "HTTP status: 200" in env_finding["evidence"]
    assert full_fake_env not in env_finding["evidence"]
    assert any(".git/HEAD" in finding["affected_url"] for finding in result["findings"])
    assert all("__ethiosec_missing_probe__" not in finding["affected_url"] for finding in result["findings"])


def test_exposed_files_has_no_false_positive_on_clean_target(clean_target_url):
    result = exposed_files.run(clean_target_url, _client(), depth="standard")

    assert result["findings"] == []
    assert result["checks_run"] == 26


def test_sqli_detects_database_error_on_demo_product(demo_target_url):
    target = f"{demo_target_url}/product?id=1"
    result = sqli.run(
        target,
        _client(),
        crawl_result=CrawlResult(pages=[target]),
        depth="standard",
    )

    assert result["checks_run"] == 1
    assert len(result["findings"]) == 1
    assert result["findings"][0]["parameter"] == "id"
    assert result["findings"][0]["severity"] == "high"


def test_sqli_has_no_false_positive_on_safe_demo_product(clean_target_url):
    target = f"{clean_target_url}/safe-product?id=1"
    result = sqli.run(
        target,
        _client(),
        crawl_result=CrawlResult(pages=[target]),
        depth="standard",
    )

    assert result["findings"] == []


def test_xss_detects_unencoded_demo_search_reflection(demo_target_url):
    target = f"{demo_target_url}/search?q=demo"
    result = xss.run(
        target,
        _client(),
        crawl_result=CrawlResult(pages=[target]),
        depth="standard",
    )

    assert result["checks_run"] == 1
    assert len(result["findings"]) == 1
    assert result["findings"][0]["parameter"] == "q"


def test_xss_has_no_false_positive_on_safe_demo_search(clean_target_url):
    target = f"{clean_target_url}/safe-search?q=demo"
    result = xss.run(
        target,
        _client(),
        crawl_result=CrawlResult(pages=[target]),
        depth="standard",
    )

    assert result["findings"] == []
    assert result["checks_passed"] == 1


def test_quick_depth_skips_sqli_and_xss_without_requests():
    class Client:
        def get(self, *_args, **_kwargs):
            raise AssertionError("Quick depth must not issue SQLi or XSS probes")

    for module in (sqli, xss):
        result = module.run("http://target.invalid/", Client(), depth="quick")
        assert result["checks_run"] == 0
        assert result["checks_passed"] == 0
        assert result["findings"] == []


def test_post_forms_are_not_submitted(demo_target_url):
    from demo_target import main as demo_main

    demo_main.POST_FORM_SUBMISSIONS = 0
    crawl_result = crawl_target(demo_target_url, 25, _client(), depth="standard")
    assert any(form.method == "POST" and form.input_names == ["comment"] for form in crawl_result.forms)

    client = _client()
    sqli_result = sqli.run(demo_target_url, client, crawl_result=crawl_result, depth="standard")
    xss_result = xss.run(demo_target_url, client, crawl_result=crawl_result, depth="standard")

    assert demo_main.POST_FORM_SUBMISSIONS == 0
    assert any("POST form" in note and "not tested" in note for note in sqli_result["notes"])
    assert any("POST form" in note and "not tested" in note for note in xss_result["notes"])


def test_crawler_collects_get_form_and_stays_within_page_limit(demo_target_url):
    result = crawl_target(demo_target_url, 5, _client(), depth="standard")

    assert result.pages[0] == demo_target_url
    assert len(result.pages) <= 5
    assert any(form.method == "GET" and "q" in form.input_names for form in result.forms)
    assert all(url.startswith(demo_target_url) for url in result.pages)


def test_crawler_skips_non_html_and_never_follows_off_origin_redirect():
    class Response:
        def __init__(self, status, headers, body, url):
            self.status_code = status
            self.headers = headers
            self.text = body
            self.final_url = url

    class Client:
        def __init__(self):
            self.urls = []

        def get(self, url, **kwargs):
            self.urls.append(url)
            if url.endswith("/start"):
                return Response(
                    200,
                    {"content-type": "text/html"},
                    '<a href="/asset.bin">asset</a><a href="/redirect">redirect</a><a href="https://outside.invalid/">offsite</a>',
                    url,
                )
            if url.endswith("/asset.bin"):
                return Response(200, {"content-type": "application/octet-stream"}, "bytes", url)
            return Response(
                302,
                {"location": "https://outside.invalid/landing", "content-type": "text/html"},
                "",
                url,
            )

    client = Client()
    result = crawl_target("http://local.test/start", 10, client, depth="standard")

    assert client.urls == [
        "http://local.test/start",
        "http://local.test/asset.bin",
        "http://local.test/redirect",
    ]
    assert result.pages == ["http://local.test/start"]
    assert result.discovered_urls == ["http://local.test/asset.bin"]


def test_quick_exposed_files_checks_only_well_known_paths(demo_target_url):
    class RecordingClient:
        def __init__(self):
            self.urls = []

        def get(self, url, **kwargs):
            self.urls.append(url)
            return _client().get(url, **kwargs)

    client = RecordingClient()
    result = exposed_files.run(demo_target_url, client, depth="quick")

    assert result["checks_run"] == 1
    assert client.urls == [f"{demo_target_url}/.well-known/security.txt"]
