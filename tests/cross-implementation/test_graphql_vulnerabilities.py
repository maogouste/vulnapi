"""
Cross-Implementation GraphQL Vulnerabilities Tests (G01-G05)

Tests GraphQL security vulnerabilities across all VulnAPI implementations:
- G01: Introspection enabled
- G02: No query depth limits
- G03: Batching attacks allowed
- G04: Field suggestions reveal schema
- G05: Authorization bypass

Each test runs against: Python, Go, PHP, Java, Node backends.

Usage:
    pytest tests/cross-implementation/test_graphql_vulnerabilities.py -v
    pytest tests/cross-implementation/test_graphql_vulnerabilities.py -v -k "G01"
    pytest tests/cross-implementation/test_graphql_vulnerabilities.py -v -k "go"
"""

import pytest
import httpx


class TestG01Introspection:
    """G01 - Introspection Enabled

    GraphQL introspection should be disabled in production.
    These tests verify that introspection is enabled (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_G01_introspection_reveals_schema(self, http_client, graphql_url, backend_name):
        """G01: GraphQL introspection reveals full schema."""
        query = """
        query {
            __schema {
                types {
                    name
                    fields {
                        name
                    }
                }
            }
        }
        """
        response = await http_client.post(graphql_url, json={"query": query})

        assert response.status_code == 200, f"{backend_name}: Expected 200, got {response.status_code}"
        data = response.json()

        # VULNERABILITY: Schema is exposed via introspection
        assert "data" in data, f"{backend_name}: No data in response"
        assert "__schema" in data["data"], f"{backend_name}: __schema not exposed"

        types = data["data"]["__schema"]["types"]
        type_names = [t["name"] for t in types if t["name"]]

        # Should expose User type
        assert "User" in type_names or "Query" in type_names, \
            f"{backend_name}: Internal types not exposed"

        print(f"[{backend_name}] G01 VULNERABLE: Found {len(types)} types via introspection")

    @pytest.mark.asyncio
    async def test_G01_introspection_reveals_queries(self, http_client, graphql_url, backend_name):
        """G01: Introspection reveals available queries."""
        query = """
        query {
            __schema {
                queryType {
                    name
                    fields {
                        name
                        description
                    }
                }
            }
        }
        """
        response = await http_client.post(graphql_url, json={"query": query})

        assert response.status_code == 200
        data = response.json()

        query_type = data.get("data", {}).get("__schema", {}).get("queryType")
        if query_type:
            fields = query_type.get("fields") or []
            field_names = [f["name"] for f in fields]

            # VULNERABILITY: Query operations are exposed (or queryType name is exposed)
            if len(field_names) > 0:
                print(f"[{backend_name}] G01 VULNERABLE: Exposed queries: {field_names}")
            elif query_type.get("name"):
                print(f"[{backend_name}] G01 VULNERABLE: QueryType name exposed: {query_type['name']}")

    @pytest.mark.asyncio
    async def test_G01_introspection_reveals_mutations(self, http_client, graphql_url, backend_name):
        """G01: Introspection reveals mutation operations."""
        query = """
        query {
            __schema {
                mutationType {
                    name
                    fields {
                        name
                    }
                }
            }
        }
        """
        response = await http_client.post(graphql_url, json={"query": query})

        if response.status_code == 200:
            data = response.json()
            mutation_type = data.get("data", {}).get("__schema", {}).get("mutationType")
            if mutation_type and mutation_type.get("fields"):
                mutations = [f["name"] for f in mutation_type["fields"]]
                print(f"[{backend_name}] G01 VULNERABLE: Exposed mutations: {mutations}")


class TestG02DepthLimit:
    """G02 - No Query Depth Limits

    GraphQL should enforce query depth limits to prevent DoS.
    These tests verify that deep nested queries are allowed (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_G02_deep_nested_query_allowed(self, http_client, graphql_url, backend_name):
        """G02: Deeply nested queries (5 levels) are accepted."""
        # 5-level nested query using users->orders->user circular reference
        query = """
        query {
            users {
                orders {
                    user {
                        orders {
                            user {
                                username
                            }
                        }
                    }
                }
            }
        }
        """
        response = await http_client.post(graphql_url, json={"query": query})

        assert response.status_code == 200, f"{backend_name}: Request rejected"
        data = response.json()

        # VULNERABILITY: No depth limit rejection
        has_depth_error = any(
            "depth" in str(e).lower()
            for e in data.get("errors", [])
        )
        assert not has_depth_error, f"{backend_name}: Depth limit is enforced (secure)"

        print(f"[{backend_name}] G02 VULNERABLE: Deep nested query accepted")

    @pytest.mark.asyncio
    async def test_G02_very_deep_query(self, http_client, graphql_url, backend_name):
        """G02: Very deeply nested queries (10+ levels) are accepted."""
        # Build a 10-level deep query
        query = """
        query {
            users {
                orders {
                    user {
                        orders {
                            user {
                                orders {
                                    user {
                                        orders {
                                            user {
                                                orders {
                                                    id
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        response = await http_client.post(graphql_url, json={"query": query})

        # Should either accept or timeout (both vulnerable)
        assert response.status_code in [200, 408, 504], \
            f"{backend_name}: Unexpected status {response.status_code}"

        if response.status_code == 200:
            data = response.json()
            has_depth_error = any(
                "depth" in str(e).lower()
                for e in data.get("errors", [])
            )
            if not has_depth_error:
                print(f"[{backend_name}] G02 VULNERABLE: 10-level deep query accepted")


class TestG03Batching:
    """G03 - Batching Attacks Allowed

    GraphQL should limit batch query processing to prevent DoS.
    These tests verify that batch queries are accepted (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_G03_batch_queries_accepted(self, http_client, graphql_url, backend_name):
        """G03: Multiple queries can be batched in a single request."""
        batch = [
            {"query": "{ users { id username } }"},
            {"query": "{ users { id username } }"},
            {"query": "{ users { id username } }"},
            {"query": "{ users { id username } }"},
            {"query": "{ users { id username } }"},
        ]
        response = await http_client.post(graphql_url, json=batch)

        assert response.status_code == 200, f"{backend_name}: Batch request rejected"
        data = response.json()

        # VULNERABILITY: All batched queries executed
        if isinstance(data, list):
            assert len(data) == 5, f"{backend_name}: Not all batch queries executed"
            print(f"[{backend_name}] G03 VULNERABLE: {len(data)} batched queries executed")

    @pytest.mark.asyncio
    async def test_G03_large_batch_no_limit(self, http_client, graphql_url, backend_name):
        """G03: Large batches (20 queries) are accepted without limits."""
        batch = [{"query": "{ users { id } }"} for _ in range(20)]
        response = await http_client.post(graphql_url, json=batch)

        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                # VULNERABILITY: No batch limit
                assert len(data) >= 10, f"{backend_name}: Batch limiting detected"
                print(f"[{backend_name}] G03 VULNERABLE: {len(data)} queries in batch accepted")

    @pytest.mark.asyncio
    async def test_G03_alias_batching(self, http_client, graphql_url, backend_name):
        """G03: Alias-based batching is allowed."""
        # Use aliases to execute same query multiple times
        query = """
        query {
            u1: users { id username }
            u2: users { id username }
            u3: users { id username }
            u4: users { id username }
            u5: users { id username }
        }
        """
        response = await http_client.post(graphql_url, json={"query": query})

        assert response.status_code == 200
        data = response.json()

        if "data" in data:
            aliases = ["u1", "u2", "u3", "u4", "u5"]
            found_aliases = [a for a in aliases if a in data["data"]]
            # VULNERABILITY: Multiple alias queries executed
            if len(found_aliases) == 5:
                print(f"[{backend_name}] G03 VULNERABLE: Alias batching allowed")


class TestG04FieldSuggestions:
    """G04 - Field Suggestions Reveal Schema

    GraphQL error messages should not suggest valid field names.
    These tests verify that suggestions are enabled (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_G04_field_suggestions_in_errors(self, http_client, graphql_url, backend_name):
        """G04: Typo errors reveal valid field names via suggestions."""
        # Query with intentional typo in field name
        query = """
        query {
            users {
                userna
            }
        }
        """
        response = await http_client.post(graphql_url, json={"query": query})

        assert response.status_code == 200
        data = response.json()

        errors = data.get("errors", [])
        for error in errors:
            msg = str(error.get("message", "")).lower()
            # VULNERABILITY: Field suggestions in error
            if "did you mean" in msg or "username" in msg:
                print(f"[{backend_name}] G04 VULNERABLE: Field suggestions enabled")
                print(f"    Error message: {error.get('message', '')[:100]}")
                return

        # Check if suggestions appear anywhere in error response
        error_str = str(errors).lower()
        if "did you mean" in error_str or "username" in error_str:
            print(f"[{backend_name}] G04 VULNERABLE: Field suggestions in error response")

    @pytest.mark.asyncio
    async def test_G04_type_suggestions(self, http_client, graphql_url, backend_name):
        """G04: Type errors suggest valid type names."""
        query = """
        query {
            __type(name: "Use") {
                name
            }
        }
        """
        response = await http_client.post(graphql_url, json={"query": query})

        if response.status_code == 200:
            data = response.json()
            response_str = str(data).lower()
            if "user" in response_str:
                print(f"[{backend_name}] G04 VULNERABLE: Type suggestions enabled")


class TestG05AuthBypass:
    """G05 - Authorization Bypass

    GraphQL queries should require authentication for sensitive data.
    These tests verify that data is accessible without auth (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_G05_users_query_without_auth(self, http_client, graphql_url, backend_name):
        """G05: Users query accessible without authentication."""
        query = """
        query {
            users {
                id
                username
                email
            }
        }
        """
        # No auth headers
        response = await http_client.post(graphql_url, json={"query": query})

        assert response.status_code == 200, f"{backend_name}: Request failed"
        data = response.json()

        # VULNERABILITY: Data accessible without auth
        users = data.get("data", {}).get("users", [])
        assert len(users) > 0, f"{backend_name}: No user data returned"

        print(f"[{backend_name}] G05 VULNERABLE: {len(users)} users exposed without auth")

    @pytest.mark.asyncio
    async def test_G05_sensitive_fields_exposed(self, http_client, graphql_url, backend_name):
        """G05: Sensitive user fields (SSN, creditCard) accessible."""
        query = """
        query {
            users {
                id
                username
                ssn
                creditCard
                apiKey
            }
        }
        """
        response = await http_client.post(graphql_url, json={"query": query})

        assert response.status_code == 200
        data = response.json()

        users = data.get("data", {}).get("users", [])
        for user in users:
            # VULNERABILITY: Sensitive fields exposed
            sensitive_data = {
                k: v for k, v in user.items()
                if k in ["ssn", "creditCard", "apiKey"] and v
            }
            if sensitive_data:
                print(f"[{backend_name}] G05 VULNERABLE: Sensitive fields exposed: {list(sensitive_data.keys())}")
                return

    @pytest.mark.asyncio
    async def test_G05_admin_data_exposed(self, http_client, graphql_url, backend_name):
        """G05: Admin user data accessible without authentication."""
        query = """
        query {
            users {
                id
                username
                role
            }
        }
        """
        response = await http_client.post(graphql_url, json={"query": query})

        assert response.status_code == 200
        data = response.json()

        users = data.get("data", {}).get("users", [])
        admin_users = [u for u in users if u.get("role") == "admin"]

        # VULNERABILITY: Can enumerate admin users
        if admin_users:
            admin_names = [u.get("username") for u in admin_users]
            print(f"[{backend_name}] G05 VULNERABLE: Admin users exposed: {admin_names}")

    @pytest.mark.asyncio
    async def test_G05_orders_without_auth(self, http_client, graphql_url, backend_name):
        """G05: Orders accessible without authentication."""
        query = """
        query {
            users {
                id
                username
                orders {
                    id
                    total
                }
            }
        }
        """
        response = await http_client.post(graphql_url, json={"query": query})

        if response.status_code == 200:
            data = response.json()
            users = (data.get("data") or {}).get("users") or []
            total_orders = sum(len(u.get("orders") or []) for u in users)
            if total_orders > 0:
                print(f"[{backend_name}] G05 VULNERABLE: {total_orders} orders exposed without auth")


class TestAllVulnerabilitiesSummary:
    """Summary test to check all G01-G05 vulnerabilities at once."""

    @pytest.mark.asyncio
    async def test_vulnerability_summary(self, http_client, graphql_url, backend_name):
        """Run quick check for all GraphQL vulnerabilities."""
        results = {
            "G01_introspection": False,
            "G02_depth": False,
            "G03_batching": False,
            "G04_suggestions": False,
            "G05_auth_bypass": False,
        }

        # G01: Introspection
        query = "{ __schema { types { name } } }"
        resp = await http_client.post(graphql_url, json={"query": query})
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data", {}).get("__schema"):
                results["G01_introspection"] = True

        # G02: Depth
        query = "{ users { orders { user { username } } } }"
        resp = await http_client.post(graphql_url, json={"query": query})
        if resp.status_code == 200:
            data = resp.json()
            if "depth" not in str(data.get("errors", [])).lower():
                results["G02_depth"] = True

        # G03: Batching
        batch = [{"query": "{ users { id } }"}, {"query": "{ users { id } }"}]
        resp = await http_client.post(graphql_url, json=batch)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) == 2:
                results["G03_batching"] = True

        # G04: Field suggestions
        query = "{ users { userna } }"
        resp = await http_client.post(graphql_url, json={"query": query})
        if resp.status_code == 200:
            data = resp.json()
            if "did you mean" in str(data).lower() or "username" in str(data).lower():
                results["G04_suggestions"] = True

        # G05: Auth bypass
        query = "{ users { id username } }"
        resp = await http_client.post(graphql_url, json={"query": query})
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data", {}).get("users"):
                results["G05_auth_bypass"] = True

        # Print summary
        print(f"\n[{backend_name}] VULNERABILITY SUMMARY:")
        for vuln, is_vulnerable in results.items():
            status = "VULNERABLE" if is_vulnerable else "SECURE"
            print(f"  {vuln}: {status}")

        vulnerable_count = sum(results.values())
        print(f"  Total: {vulnerable_count}/5 vulnerabilities present")

        # Assert that most vulnerabilities exist (as intended for training)
        assert vulnerable_count >= 3, \
            f"{backend_name}: Expected at least 3/5 G01-G05 vulnerabilities for training purposes"
