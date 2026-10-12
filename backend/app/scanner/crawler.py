"""Same-origin page discovery through the SSRF-protected HTTP client."""

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable, Optional
from urllib.parse import urldefrag, urljoin, urlsplit


PAGE_LIMITS = {"quick": 5, "standard": 25, "deep": 100}


@dataclass
class CrawlForm:
	page_url: str
	action_url: str
	method: str
	input_names: list[str] = field(default_factory=list)
	input_types: dict[str, str] = field(default_factory=dict)


@dataclass
class CrawlResult:
	pages: list[str] = field(default_factory=list)
	discovered_urls: list[str] = field(default_factory=list)
	forms: list[CrawlForm] = field(default_factory=list)


class _PageParser(HTMLParser):
	def __init__(self) -> None:
		super().__init__()
		self.links: list[str] = []
		self.forms: list[dict] = []
		self.current_form: Optional[dict] = None

	def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
		attributes = {name.lower(): value for name, value in attrs}
		if tag.lower() == "a" and attributes.get("href"):
			self.links.append(attributes["href"])
		elif tag.lower() == "form":
			self.current_form = {
				"action": attributes.get("action") or "",
				"method": (attributes.get("method") or "GET").upper(),
				"input_names": [],
				"input_types": {},
			}
			self.forms.append(self.current_form)
		elif tag.lower() in {"input", "textarea", "select"} and self.current_form:
			name = attributes.get("name")
			if name:
				self.current_form["input_names"].append(name)
				if tag.lower() == "input":
					self.current_form["input_types"][name] = (
						attributes.get("type") or "text"
					).lower()

	def handle_endtag(self, tag: str) -> None:
		if tag.lower() == "form":
			self.current_form = None


def crawl_target(
	target_url: str,
	max_pages: int,
	client,
	should_cancel: Optional[Callable[[], bool]] = None,
	depth: str = "standard",
) -> CrawlResult:
	"""Discover same-origin HTML pages and form inputs up to max_pages."""
	origin = urlsplit(target_url)
	origin_key = (origin.scheme.lower(), (origin.hostname or "").lower(), origin.port)
	queue = deque([target_url])
	result = CrawlResult()
	queued = {target_url}
	fetched_count = 0

	while queue and fetched_count < max_pages:
		if should_cancel and should_cancel():
			break

		url = queue.popleft()
		fetched_count += 1
		response = client.get(url, follow_redirects=False)
		if response.status_code in (301, 302, 303, 307, 308):
			if url in result.discovered_urls:
				result.discovered_urls.remove(url)
			location = response.headers.get("location")
			if location:
				redirect_url, _fragment = urldefrag(urljoin(url, location))
				redirect_parts = urlsplit(redirect_url)
				redirect_origin = (
					redirect_parts.scheme.lower(),
					(redirect_parts.hostname or "").lower(),
					redirect_parts.port,
				)
				if redirect_origin == origin_key and redirect_url not in queued:
					queue.appendleft(redirect_url)
					queued.add(redirect_url)
			continue
		content_type = response.headers.get("content-type", "").lower()
		if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
			continue
		page_url = response.final_url
		page_parts = urlsplit(page_url)
		page_origin = (page_parts.scheme.lower(), (page_parts.hostname or "").lower(), page_parts.port)
		if page_origin != origin_key:
			continue
		result.pages.append(page_url)
		parser = _PageParser()
		parser.feed(response.text)
		for form in parser.forms:
			action_url = urljoin(page_url, form["action"])
			action_parts = urlsplit(action_url)
			action_origin = (
				action_parts.scheme.lower(),
				(action_parts.hostname or "").lower(),
				action_parts.port,
			)
			if action_origin != origin_key:
				continue
			result.forms.append(
				CrawlForm(
					page_url=page_url,
					action_url=action_url,
					method=form["method"],
					input_names=form["input_names"],
					input_types=form["input_types"],
				)
			)

		for href in parser.links:
			if depth == "quick":
				continue
			candidate, _fragment = urldefrag(urljoin(page_url, href))
			parsed = urlsplit(candidate)
			candidate_key = (
				parsed.scheme.lower(),
				(parsed.hostname or "").lower(),
				parsed.port,
			)
			if (
				parsed.scheme.lower() in ("http", "https")
				and candidate_key == origin_key
				and candidate not in queued
				and len(result.pages) + len(queue) < max_pages
			):
				result.discovered_urls.append(candidate)
				queue.append(candidate)
				queued.add(candidate)

	return result
