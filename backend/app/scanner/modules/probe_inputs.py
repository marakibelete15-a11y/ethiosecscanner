"""Shared safe GET-parameter discovery for passive-to-active probe modules."""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.scanner.crawler import CrawlResult


def get_parameter_targets(crawl_result: CrawlResult) -> tuple[list[tuple[str, str]], list[str]]:
	"""Return unique (URL-with-parameter, parameter-name) pairs and POST forms not tested."""
	targets: list[tuple[str, str]] = []
	seen: set[tuple[str, str]] = set()
	for page_url in dict.fromkeys(crawl_result.pages + crawl_result.discovered_urls):
		parsed = urlsplit(page_url)
		for parameter, _value in parse_qsl(parsed.query, keep_blank_values=True):
			pair = (page_url, parameter)
			if pair not in seen:
				seen.add(pair)
				targets.append(pair)
	for form in crawl_result.forms:
		if form.method == "POST":
			continue
		if form.method != "GET":
			continue
		parsed = urlsplit(form.action_url)
		query_items = parse_qsl(parsed.query, keep_blank_values=True)
		for parameter in form.input_names:
			new_items = list(query_items)
			if parameter not in {name for name, _value in new_items}:
				new_items.append((parameter, ""))
			query = urlencode(new_items, doseq=True)
			url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
			pair = (url, parameter)
			if pair not in seen:
				seen.add(pair)
				targets.append(pair)
	return targets, [
		f"POST form at {form.page_url} ({form.action_url}) not tested; inputs: {', '.join(form.input_names)}"
		for form in crawl_result.forms
		if form.method == "POST"
	]


def replace_parameter(url: str, parameter: str, value: str) -> str:
	parsed = urlsplit(url)
	items = parse_qsl(parsed.query, keep_blank_values=True)
	updated = [(name, value if name == parameter else current) for name, current in items]
	return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(updated, doseq=True), ""))