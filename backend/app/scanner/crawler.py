"""Same-origin page discovery through the SSRF-protected HTTP client."""

from collections import deque
from html.parser import HTMLParser
from typing import Callable, Optional
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit


PAGE_LIMITS = {"quick": 5, "standard": 25, "deep": 100}


class _LinkParser(HTMLParser):
	def __init__(self) -> None:
		super().__init__()
		self.links: list[str] = []

	def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
		if tag.lower() == "a":
			for name, value in attrs:
				if name.lower() == "href" and value:
					self.links.append(value)


def crawl_target(
	target_url: str,
	max_pages: int,
	client,
	should_cancel: Optional[Callable[[], bool]] = None,
) -> list[str]:
	"""Return up to max_pages same-origin URLs, beginning with the home page."""
	origin = urlsplit(target_url)
	origin_key = (origin.scheme.lower(), (origin.hostname or "").lower(), origin.port)
	queue = deque([target_url])
	visited: list[str] = []
	queued = {target_url}

	while queue and len(visited) < max_pages:
		if should_cancel and should_cancel():
			break

		url = queue.popleft()
		response = client.get(url)
		visited.append(url)
		parser = _LinkParser()
		parser.feed(response.text)

		for href in parser.links:
			candidate, _fragment = urldefrag(urljoin(response.final_url, href))
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
				and len(visited) + len(queue) < max_pages
			):
				queue.append(candidate)
				queued.add(candidate)

	return visited
