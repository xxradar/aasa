"""Scanner for well-known API documentation and specification endpoints."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from urllib.parse import urljoin

import httpx

from config import settings
from models import Finding, FindingCategory, Severity

logger = logging.getLogger(__name__)


class APIEndpoint:
    """A discovered API endpoint."""

    def __init__(
        self,
        url: str,
        path: str,
        status_code: int,
        content_type: str = "",
        size: int = 0,
        endpoint_type: str = "unknown",
        spec_data: dict | None = None,
        title: str = "",
        snippet: str = "",
    ):
        self.url = url
        self.path = path
        self.status_code = status_code
        self.content_type = content_type
        self.size = size
        self.endpoint_type = endpoint_type  # openapi, swagger, graphql, health, admin, etc.
        self.spec_data = spec_data
        self.title = title
        self.snippet = snippet


class APIDiscoveryScanner:
    """Probes target for well-known API documentation and spec endpoints.

    Used in two modes:
    1. During website scans — probe paths from config.api_discovery_paths
    2. Standalone API scan — deeper analysis with optional endpoint testing
    """

    def __init__(self, base_url: str, llm_judge=None):
        self.base_url = base_url.rstrip("/")
        self.llm_judge = llm_judge  # Optional LLMJudgeAnalyzer instance

    async def discover(self, probe_endpoints: bool = False) -> tuple[list[APIEndpoint], list[Finding]]:
        """Probe all well-known API paths.

        Args:
            probe_endpoints: If True, parse discovered specs and probe
                             individual API endpoints for accessibility.

        Returns:
            (discovered_endpoints, findings)
        """
        endpoints: list[APIEndpoint] = []
        findings: list[Finding] = []

        async with httpx.AsyncClient(
            timeout=settings.request_timeout,
            follow_redirects=True,
            headers={"User-Agent": settings.user_agent},
            verify=False,
        ) as client:
            # Phase 1: Probe well-known paths + the root URL itself
            tasks = [self._probe_root(client)]
            tasks.extend(
                self._probe_path(client, path)
                for path in settings.api_discovery_paths
            )
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, APIEndpoint):
                    endpoints.append(result)
                elif isinstance(result, Exception):
                    logger.debug(f"API discovery probe error: {result}")

            # Generate findings for discovered endpoints
            for ep in endpoints:
                findings.extend(self._assess_endpoint(ep))

            # Phase 2: If we found OpenAPI/Swagger specs, parse and optionally test
            spec_endpoints = [
                ep for ep in endpoints
                if ep.spec_data and ep.endpoint_type in ("openapi", "swagger")
            ]

            # Phase 2a: LLM deep review of discovered specs
            if self.llm_judge and self.llm_judge.available and spec_endpoints:
                logger.info(
                    f"LLM reviewing {len(spec_endpoints)} API spec(s)..."
                )
                # Collect static findings for context
                static_api_findings = list(findings)
                for ep in spec_endpoints:
                    try:
                        llm_findings = await self.llm_judge.analyze_api_spec(
                            spec_url=ep.url,
                            spec_data=ep.spec_data,
                            static_findings=static_api_findings,
                        )
                        findings.extend(llm_findings)
                        logger.info(
                            f"LLM spec review of {ep.url}: {len(llm_findings)} findings"
                        )
                    except Exception as e:
                        logger.error(f"LLM spec review failed for {ep.url}: {e}")

            # Phase 2b: Active endpoint probing
            probed_responses: list[dict] = []
            if probe_endpoints:
                if spec_endpoints:
                    logger.info(
                        f"Active scanning: found {len(spec_endpoints)} OpenAPI/Swagger spec(s), "
                        f"probing their endpoints..."
                    )
                    for ep in spec_endpoints:
                        spec_findings, responses = await self._analyze_spec(client, ep)
                        findings.extend(spec_findings)
                        probed_responses.extend(responses)
                else:
                    logger.info(
                        "Active scanning requested but no OpenAPI/Swagger specs were discovered — "
                        "nothing to probe. Only well-known path scan results available."
                    )

            # Phase 2c: LLM review of probed response bodies
            if self.llm_judge and self.llm_judge.available and probed_responses:
                logger.info(
                    f"LLM reviewing {len(probed_responses)} probed API response(s)..."
                )
                try:
                    resp_findings = await self.llm_judge.analyze_api_responses(
                        base_url=self.base_url,
                        probed_responses=probed_responses,
                    )
                    findings.extend(resp_findings)
                    logger.info(
                        f"LLM response review: {len(resp_findings)} findings"
                    )
                except Exception as e:
                    logger.error(f"LLM response review failed: {e}")

        return endpoints, findings

    async def _probe_root(self, client: httpx.AsyncClient) -> APIEndpoint | None:
        """Check if the root URL itself serves an API spec (JSON/YAML)."""
        url = self.base_url + "/"
        try:
            resp = await client.get(url)
        except Exception:
            return None

        if resp.status_code >= 400:
            return None

        ct = resp.headers.get("content-type", "")
        body = resp.text[:50_000]

        # Only interesting if root returns JSON that looks like a spec
        if "json" not in ct and not body.lstrip().startswith("{"):
            return None

        endpoint_type = self._classify_endpoint("", ct, body)
        if endpoint_type not in ("openapi", "swagger"):
            return None

        spec_data = None
        try:
            spec_data = json.loads(body)
        except json.JSONDecodeError:
            return None

        title = ""
        if spec_data:
            title = spec_data.get("info", {}).get("title", "")

        logger.info(
            f"API spec at root URL: {url} "
            f"(type={endpoint_type}, title={title})"
        )

        return APIEndpoint(
            url=url,
            path="/",
            status_code=resp.status_code,
            content_type=ct,
            size=len(body),
            endpoint_type=endpoint_type,
            spec_data=spec_data,
            title=title,
            snippet=body[:500],
        )

    async def _probe_path(
        self, client: httpx.AsyncClient, path: str
    ) -> APIEndpoint | None:
        """Check if a specific API path exists and classify it."""
        url = urljoin(self.base_url + "/", path)

        try:
            resp = await client.get(url)
        except Exception as e:
            logger.debug(f"Could not reach {url}: {e}")
            return None

        ct = resp.headers.get("content-type", "")
        body = resp.text[:50_000]

        # For most paths, skip client/server errors
        # But for health/admin/debug, a 5xx still confirms the endpoint exists
        if resp.status_code >= 400:
            interesting_on_error = any(
                x in path.lower()
                for x in ["health", "healthz", "readyz", "admin", "debug",
                           "actuator", "status", "_status", "_health"]
            )
            if not (interesting_on_error and resp.status_code >= 500):
                return None

        # Skip tiny or empty responses
        if len(body.strip()) < 5:
            return None

        # Skip responses that are clearly just HTML homepage redirects
        if "text/html" in ct and resp.status_code == 200:
            # Check if it looks like API docs vs generic page
            if not self._looks_like_api_doc(body, path):
                return None

        endpoint_type = self._classify_endpoint(path, ct, body)
        if not endpoint_type:
            return None

        # Try to parse spec data for OpenAPI/Swagger
        spec_data = None
        if endpoint_type in ("openapi", "swagger") and ("json" in ct or body.lstrip().startswith("{")):
            try:
                spec_data = json.loads(body)
            except json.JSONDecodeError:
                pass

        title = ""
        if spec_data:
            info = spec_data.get("info", {})
            title = info.get("title", "")

        logger.info(
            f"API endpoint discovered: {url} "
            f"(type={endpoint_type}, status={resp.status_code}, size={len(body)})"
        )

        return APIEndpoint(
            url=url,
            path=path,
            status_code=resp.status_code,
            content_type=ct,
            size=len(body),
            endpoint_type=endpoint_type,
            spec_data=spec_data,
            title=title,
            snippet=body[:500],
        )

    def _looks_like_api_doc(self, body: str, path: str) -> bool:
        """Heuristic: does this HTML look like API documentation?"""
        lower = body.lower()
        indicators = [
            "swagger", "openapi", "redoc", "graphql", "graphiql",
            "api-docs", "api documentation", "api reference",
            "rapidoc", "stoplight", "scalar",
            '"paths"', '"openapi"', '"swagger"',
            "playground", "introspection",
        ]
        # Path-based hints
        path_hints = ["docs", "swagger", "redoc", "graphql", "graphiql", "playground"]
        has_path_hint = any(h in path.lower() for h in path_hints)

        return has_path_hint or any(ind in lower for ind in indicators)

    def _classify_endpoint(self, path: str, ct: str, body: str) -> str | None:
        """Classify a discovered endpoint by type."""
        lower_path = path.lower()
        lower_body = body[:2000].lower()

        # OpenAPI 3.x
        if '"openapi"' in lower_body or "'openapi'" in lower_body:
            return "openapi"

        # Swagger 2.x
        if '"swagger"' in lower_body:
            return "swagger"

        # Swagger UI / ReDoc pages
        if any(x in lower_path for x in ["swagger-ui", "swagger.html"]):
            return "swagger_ui"
        if "redoc" in lower_path:
            return "redoc"

        # GraphQL
        if "graphql" in lower_path or "graphiql" in lower_path or "playground" in lower_path:
            if '"data"' in lower_body or "graphql" in lower_body or "query" in lower_body:
                return "graphql"

        # Health/status
        if any(x in lower_path for x in ["health", "healthz", "readyz", "_health"]):
            return "health"
        if any(x in lower_path for x in ["status", "_status"]):
            return "status"

        # Actuator (Spring Boot)
        if "actuator" in lower_path:
            return "actuator"

        # Metrics
        if "metrics" in lower_path or "prometheus" in lower_path:
            return "metrics"

        # Admin/debug
        if any(x in lower_path for x in ["admin", "_admin"]):
            return "admin"
        if any(x in lower_path for x in ["debug", "_debug"]):
            return "debug"

        # Generic API listing
        if lower_path.rstrip("/") in ("api", "api/v1", "api/v2", "api/v3"):
            if "application/json" in ct:
                return "api_root"

        # JSON spec files
        if any(x in lower_path for x in ["schema", "api-spec", "api-docs"]):
            if "json" in ct or body.lstrip().startswith("{"):
                return "api_spec"

        return None

    def _assess_endpoint(self, ep: APIEndpoint) -> list[Finding]:
        """Generate findings based on a discovered API endpoint."""
        findings = []

        # Base discovery finding
        severity = self._severity_for_type(ep.endpoint_type)
        findings.append(Finding(
            category=FindingCategory.agentic_signal,
            severity=severity,
            title=f"API endpoint discovered: {ep.path} ({ep.endpoint_type})",
            description=(
                f"The {ep.endpoint_type} endpoint '{ep.path}' is publicly accessible at {ep.url}. "
                f"Status: {ep.status_code}, Content-Type: {ep.content_type}, Size: {ep.size} bytes."
                + (f" API title: {ep.title}." if ep.title else "")
            ),
            evidence=ep.snippet[:300],
            url=ep.url,
            analyzer="api_discovery",
            recommendation=self._recommendation_for_type(ep.endpoint_type),
        ))

        # Extra findings for spec content
        if ep.spec_data:
            findings.extend(self._analyze_spec_content(ep))

        return findings

    def _analyze_spec_content(self, ep: APIEndpoint) -> list[Finding]:
        """Analyze OpenAPI/Swagger spec for security concerns."""
        findings = []
        spec = ep.spec_data
        if not spec:
            return findings

        # Count paths
        paths = spec.get("paths", {})
        path_count = len(paths)

        # Check for auth schemes
        security = spec.get("security", [])
        security_defs = (
            spec.get("securityDefinitions", {})  # Swagger 2
            or spec.get("components", {}).get("securitySchemes", {})  # OpenAPI 3
        )

        if not security and not security_defs:
            findings.append(Finding(
                category=FindingCategory.agentic_signal,
                severity=Severity.high,
                title="API spec has no security definitions",
                description=(
                    f"The OpenAPI spec at {ep.url} defines {path_count} endpoints "
                    "but has no security schemes (no authentication/authorization). "
                    "This API may be fully unauthenticated."
                ),
                evidence=f"Paths: {path_count}, Security definitions: none",
                url=ep.url,
                analyzer="api_discovery",
                recommendation="Add authentication (API key, OAuth2, JWT) to protect API endpoints.",
            ))

        # Check for sensitive-looking endpoints
        sensitive_patterns = [
            (r"/admin", "admin"),
            (r"/user", "user data"),
            (r"/auth", "authentication"),
            (r"/token", "token"),
            (r"/password", "password"),
            (r"/secret", "secret"),
            (r"/internal", "internal"),
            (r"/debug", "debug"),
            (r"/config", "configuration"),
            (r"/env", "environment"),
            (r"/database", "database"),
            (r"/backup", "backup"),
            (r"/export", "export"),
            (r"/upload", "file upload"),
            (r"/execute", "execution"),
            (r"/eval", "evaluation"),
            (r"/shell", "shell"),
            (r"/cmd", "command"),
        ]

        sensitive_found = []
        for api_path in paths:
            for pattern, label in sensitive_patterns:
                if re.search(pattern, api_path, re.IGNORECASE):
                    sensitive_found.append((api_path, label))
                    break

        if sensitive_found:
            details = ", ".join(f"{p} ({l})" for p, l in sensitive_found[:10])
            findings.append(Finding(
                category=FindingCategory.agentic_signal,
                severity=Severity.high,
                title=f"API spec exposes {len(sensitive_found)} sensitive endpoints",
                description=(
                    f"The API spec at {ep.url} contains endpoints that handle "
                    f"sensitive operations: {details}. "
                    "An AI agent could discover and interact with these endpoints."
                ),
                evidence=details,
                url=ep.url,
                analyzer="api_discovery",
                recommendation="Ensure sensitive endpoints require proper authentication and are not exposed publicly.",
            ))

        # Check for data in examples/defaults
        info = spec.get("info", {})
        spec_str = json.dumps(spec)[:10000].lower()
        if any(tok in spec_str for tok in ["api_key", "apikey", "bearer", "password", "secret", "token"]):
            findings.append(Finding(
                category=FindingCategory.exfiltration,
                severity=Severity.medium,
                title="API spec may contain credential references",
                description=(
                    f"The API specification at {ep.url} contains references to "
                    "credentials (api_key, bearer, password, secret, token). "
                    "Check if any real credentials are leaked in examples or defaults."
                ),
                evidence="Credential-related keywords found in spec",
                url=ep.url,
                analyzer="api_discovery",
                recommendation="Remove any hardcoded credentials from API spec examples and defaults.",
            ))

        # Summary finding
        methods_count = sum(len(v) for v in paths.values() if isinstance(v, dict))
        servers = spec.get("servers", [])
        server_urls = [s.get("url", "") for s in servers] if servers else []
        findings.append(Finding(
            category=FindingCategory.agentic_signal,
            severity=Severity.info,
            title=f"API spec summary: {path_count} paths, {methods_count} operations",
            description=(
                f"OpenAPI spec at {ep.url}: "
                f"Title: {info.get('title', 'N/A')}, "
                f"Version: {info.get('version', 'N/A')}, "
                f"Paths: {path_count}, "
                f"Operations: {methods_count}, "
                f"Servers: {', '.join(server_urls) or 'N/A'}, "
                f"Auth schemes: {len(security_defs)}."
            ),
            evidence=f"title={info.get('title', '')}, version={info.get('version', '')}",
            url=ep.url,
            analyzer="api_discovery",
        ))

        return findings

    async def _analyze_spec(
        self, client: httpx.AsyncClient, ep: APIEndpoint
    ) -> tuple[list[Finding], list[dict]]:
        """Parse spec and probe individual endpoints (active scanning).

        Returns:
            (findings, probed_responses) — probed_responses is a list of dicts
            with keys: path, status_code, content_type, body for LLM analysis.
        """
        findings = []
        probed_responses: list[dict] = []
        spec = ep.spec_data
        if not spec:
            return findings, probed_responses

        paths = spec.get("paths", {})
        # Determine base URL from spec servers
        servers = spec.get("servers", [])
        api_base = servers[0].get("url", "") if servers else ""
        if api_base.startswith("/"):
            api_base = self.base_url + api_base
        elif not api_base.startswith("http"):
            api_base = self.base_url

        # Probe GET endpoints only (safe)
        probed = 0
        unprotected = []
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            if "get" not in methods:
                continue
            if probed >= 20:  # cap at 20 probes
                break

            full_url = api_base.rstrip("/") + path
            # Skip paths with path params we can't fill
            if "{" in path:
                continue

            probed += 1
            try:
                resp = await client.get(full_url)
                ct = resp.headers.get("content-type", "")
                body = resp.text[:5000]

                # Collect response for LLM analysis
                probed_responses.append({
                    "path": path,
                    "status_code": resp.status_code,
                    "content_type": ct,
                    "body": body,
                })

                if resp.status_code < 400:
                    unprotected.append((path, resp.status_code))
            except Exception:
                pass

        if unprotected:
            details = ", ".join(f"{p} ({s})" for p, s in unprotected[:10])
            findings.append(Finding(
                category=FindingCategory.agentic_signal,
                severity=Severity.high,
                title=f"{len(unprotected)} API endpoints accessible without auth",
                description=(
                    f"Probed {probed} GET endpoints from the API spec. "
                    f"{len(unprotected)} returned success without authentication: {details}."
                ),
                evidence=details,
                url=ep.url,
                analyzer="api_discovery",
                recommendation="Add authentication to API endpoints or restrict access.",
            ))

        return findings, probed_responses

    def _severity_for_type(self, endpoint_type: str) -> Severity:
        """Map endpoint type to finding severity."""
        return {
            "openapi": Severity.medium,
            "swagger": Severity.medium,
            "swagger_ui": Severity.medium,
            "redoc": Severity.medium,
            "graphql": Severity.high,
            "health": Severity.info,
            "status": Severity.info,
            "actuator": Severity.high,
            "metrics": Severity.medium,
            "admin": Severity.critical,
            "debug": Severity.critical,
            "api_root": Severity.low,
            "api_spec": Severity.medium,
        }.get(endpoint_type, Severity.info)

    def _recommendation_for_type(self, endpoint_type: str) -> str:
        """Map endpoint type to recommendation."""
        return {
            "openapi": "Restrict API documentation access to authorized users in production.",
            "swagger": "Restrict Swagger UI/spec access to authorized users in production.",
            "swagger_ui": "Disable Swagger UI in production or restrict access.",
            "redoc": "Restrict ReDoc access to authorized users in production.",
            "graphql": "Disable GraphQL introspection in production and enforce authentication.",
            "health": "Health endpoints are generally safe but may leak version information.",
            "status": "Status endpoints may leak internal system details.",
            "actuator": "Spring Boot Actuator endpoints can leak sensitive config. Restrict access immediately.",
            "metrics": "Prometheus/metrics endpoints may expose internal system state.",
            "admin": "Admin interfaces must be protected with strong authentication.",
            "debug": "Debug endpoints must be disabled in production — they expose internal state.",
            "api_root": "API root listing may help attackers enumerate available endpoints.",
            "api_spec": "API specification files help attackers understand your API surface.",
        }.get(endpoint_type, "Review whether this endpoint should be publicly accessible.")
