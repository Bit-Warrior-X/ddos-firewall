# core/redis_client.py
"""Redis client operations for ACL rules."""
import redis
import json
import time
from datetime import datetime
from typing import Any, List, Dict, Optional
import config

class RedisClient:
    """Manages Redis operations for ACL rules."""
    
    @staticmethod
    def get_client():
        """Get Redis client instance."""
        return redis.Redis(
            unix_socket_path=config.REDIS_SOCK,
            db=config.REDIS_DB,
            decode_responses=True
        )
    
    @staticmethod
    def store_acl_rules(rules_data: List[Dict]) -> tuple:
        """Store ACL rules in Redis."""
        try:
            rcli = RedisClient.get_client()
            
            # Get existing IDs
            orig_members = rcli.smembers(config.RULE_IDS_KEY) or set()
            orig_ids = set()
            for m in orig_members:
                try:
                    orig_ids.add(int(m) if isinstance(m, (int, str)) else int(m.decode()))
                except Exception:
                    pass
            
            prepared_ids = {r['id'] for r in rules_data}
            
            # Store new/updated rules
            pipe = rcli.pipeline()
            for rule in rules_data:
                key = f"acl_rule:{rule['id']}"
                value = json.dumps(rule, ensure_ascii=False, indent=2).replace('\\/', '/')
                pipe.set(key, value)
                pipe.sadd(config.RULE_IDS_KEY, rule['id'])
                pipe.publish("acl:updates", f"acl_rule:{rule['id']}")
            pipe.execute()
            
            # Remove deleted rules
            to_remove = sorted(list(orig_ids - prepared_ids))
            if to_remove:
                del_pipe = rcli.pipeline()
                for rid in to_remove:
                    del_key = f"acl_rule:{rid}"
                    del_pipe.delete(del_key)
                    del_pipe.srem(config.RULE_IDS_KEY, rid)
                    del_pipe.publish("acl:updates", f"acl_rule_deleted:{rid}")
                del_pipe.execute()
            
            return True, f"Stored {len(rules_data)} ACL rules"
        except Exception as e:
            return False, f"Redis error: {str(e)}"
    
    @staticmethod
    def get_acl_rules() -> List[Dict]:
        """Retrieve all ACL rules from Redis."""
        try:
            rcli = RedisClient.get_client()
            ids = rcli.smembers(config.RULE_IDS_KEY) or set()
            
            results = []
            for sid in sorted(ids, key=lambda x: int(x) if str(x).isdigit() else x):
                key = f"acl_rule:{sid}"
                try:
                    val = rcli.get(key)
                    if val:
                        obj = json.loads(val)
                        results.append(obj)
                except Exception:
                    continue
            
            return results
        except Exception as e:
            raise Exception(f"Failed to read ACL rules: {e}")
    
    @staticmethod
    def store_acl_apply_rules(rules: List[Dict]) -> bool:
        """Store ACL apply rules in Redis."""
        try:
            rcli = RedisClient.get_client()
            json_val = json.dumps(rules, separators=(",", ":"), ensure_ascii=False, indent=2).replace('\\/', '/')
            pipe = rcli.pipeline()
            pipe.set("acl_apply_rules", json_val)
            pipe.publish("acl:updates", "acl_apply_rules")
            pipe.execute()
            return True
        except Exception:
            return False
    
    @staticmethod
    def get_acl_apply_rules() -> List[Dict]:
        """Retrieve ACL apply rules from Redis."""
        try:
            rcli = RedisClient.get_client()
            val = rcli.get("acl_apply_rules")
            if not val:
                return []
            return json.loads(val)
        except Exception:
            return []

    WHITELIST_KEY = "whitelist"

    @staticmethod
    def store_whitelist(whitelist_payload: Dict) -> tuple:
        """Store L7 whitelist rules in Redis under key 'whitelist'.

        whitelist_payload must have: id (int), rules (list of {action, priority, rule}).
        Returns (True, None) on success, (False, error_message) on failure.
        """
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                whitelist_payload,
                ensure_ascii=False,
                indent=2
            ).replace("\\/", "/")
            rcli.set(RedisClient.WHITELIST_KEY, value)
            rcli.publish("acl:updates", RedisClient.WHITELIST_KEY)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_whitelist() -> Dict:
        """Retrieve L7 whitelist from Redis."""
        try:
            rcli = RedisClient.get_client()
            val = rcli.get(RedisClient.WHITELIST_KEY)
            if not val:
                return {}
            return json.loads(val)
        except Exception:
            return {}

    BLACKLIST_KEY = "blacklist"

    @staticmethod
    def store_blacklist(blacklist_payload: Dict) -> tuple:
        """Store L7 blacklist rules in Redis under key 'blacklist'.

        blacklist_payload must have: id (int), rules (list of {action, priority, rule}).
        Returns (True, None) on success, (False, error_message) on failure.
        """
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                blacklist_payload,
                ensure_ascii=False,
                indent=2
            ).replace("\\/", "/")
            rcli.set(RedisClient.BLACKLIST_KEY, value)
            rcli.publish("acl:updates", RedisClient.BLACKLIST_KEY)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_blacklist() -> Dict:
        """Retrieve L7 blacklist from Redis."""
        try:
            rcli = RedisClient.get_client()
            val = rcli.get(RedisClient.BLACKLIST_KEY)
            if not val:
                return {}
            return json.loads(val)
        except Exception:
            return {}

    GEO_KEY = "geo"

    @staticmethod
    def store_geo(geo_payload: Dict) -> tuple:
        """Store L7 geo rules in Redis under key 'geo'.

        geo_payload must have: id (int), rules (list of {action, priority, rule}).
        Returns (True, None) on success, (False, error_message) on failure.
        """
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                geo_payload,
                ensure_ascii=False,
                indent=2
            ).replace("\\/", "/")
            rcli.set(RedisClient.GEO_KEY, value)
            rcli.publish("acl:updates", RedisClient.GEO_KEY)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_geo() -> Dict:
        """Retrieve L7 geo rules from Redis."""
        try:
            rcli = RedisClient.get_client()
            val = rcli.get(RedisClient.GEO_KEY)
            if not val:
                return {}
            return json.loads(val)
        except Exception:
            return {}

    ANTIHEADER_KEY = "antiheader"

    @staticmethod
    def store_antiheader(anti_payload: Dict) -> tuple:
        """Store L7 anti-header rules in Redis under key 'antiheader'.

        anti_payload must have: id (int), rules (list of {action, priority, rule}).
        Returns (True, None) on success, (False, error_message) on failure.
        """
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                anti_payload,
                ensure_ascii=False,
                indent=2
            ).replace("\\/", "/")
            rcli.set(RedisClient.ANTIHEADER_KEY, value)
            rcli.publish("acl:updates", RedisClient.ANTIHEADER_KEY)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_antiheader() -> Dict:
        """Retrieve L7 anti-header rules from Redis."""
        try:
            rcli = RedisClient.get_client()
            val = rcli.get(RedisClient.ANTIHEADER_KEY)
            if not val:
                return {}
            return json.loads(val)
        except Exception:
            return {}

    INTERVALFREQLIMIT_KEY = "intervalfreqlimit"

    @staticmethod
    def store_intervalfreqlimit(payload: Dict) -> tuple:
        """Store L7 interval frequency limit rules in Redis under key 'intervalfreqlimit'.

        payload must have: id (int), rules (list of {action, priority, rule}).
        Returns (True, None) on success, (False, error_message) on failure.
        """
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                payload,
                ensure_ascii=False,
                indent=2
            ).replace("\\/", "/")
            rcli.set(RedisClient.INTERVALFREQLIMIT_KEY, value)
            rcli.publish("acl:updates", RedisClient.INTERVALFREQLIMIT_KEY)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_intervalfreqlimit() -> Dict:
        """Retrieve L7 interval frequency limit rules from Redis."""
        try:
            rcli = RedisClient.get_client()
            val = rcli.get(RedisClient.INTERVALFREQLIMIT_KEY)
            if not val:
                return {}
            return json.loads(val)
        except Exception:
            return {}

    SECONDFREQLIMIT_KEY = "secondfreqlimit"

    @staticmethod
    def store_secondfreqlimit(payload: Dict) -> tuple:
        """Store L7 second frequency limit rules in Redis under key 'secondfreqlimit'.

        payload must have: id (int), rules (list of {action, priority, rule}).
        Returns (True, None) on success, (False, error_message) on failure.
        """
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                payload,
                ensure_ascii=False,
                indent=2
            ).replace("\\/", "/")
            rcli.set(RedisClient.SECONDFREQLIMIT_KEY, value)
            rcli.publish("acl:updates", RedisClient.SECONDFREQLIMIT_KEY)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_secondfreqlimit() -> Dict:
        """Retrieve L7 second frequency limit rules from Redis."""
        try:
            rcli = RedisClient.get_client()
            val = rcli.get(RedisClient.SECONDFREQLIMIT_KEY)
            if not val:
                return {}
            return json.loads(val)
        except Exception:
            return {}

    RESPONSEFREQ_KEY = "responsefreq"

    @staticmethod
    def store_responsefreq(payload: Dict) -> tuple:
        """Store L7 response frequency rules in Redis under key 'responsefreq'.

        payload must have: id (int), rules (list of {action, priority, rule}).
        Returns (True, None) on success, (False, error_message) on failure.
        """
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                payload,
                ensure_ascii=False,
                indent=2
            ).replace("\\/", "/")
            rcli.set(RedisClient.RESPONSEFREQ_KEY, value)
            rcli.publish("acl:updates", RedisClient.RESPONSEFREQ_KEY)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_responsefreq() -> Dict:
        """Retrieve L7 response frequency rules from Redis."""
        try:
            rcli = RedisClient.get_client()
            val = rcli.get(RedisClient.RESPONSEFREQ_KEY)
            if not val:
                return {}
            return json.loads(val)
        except Exception:
            return {}

    USERAGENT_KEY = "useragent"

    @staticmethod
    def store_useragent(payload: Dict) -> tuple:
        """Store L7 user-agent rules in Redis under key 'useragent'.

        payload must have: id (int), rules (list of {action, priority, rule}).
        Returns (True, None) on success, (False, error_message) on failure.
        """
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                payload,
                ensure_ascii=False,
                indent=2
            ).replace("\\/", "/")
            rcli.set(RedisClient.USERAGENT_KEY, value)
            rcli.publish("acl:updates", RedisClient.USERAGENT_KEY)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_useragent() -> Dict:
        """Retrieve L7 user-agent rules from Redis."""
        try:
            rcli = RedisClient.get_client()
            val = rcli.get(RedisClient.USERAGENT_KEY)
            if not val:
                return {}
            return json.loads(val)
        except Exception:
            return {}

    UPSTREAMSERVERS_KEY = "upstreamservers"

    @staticmethod
    def store_upstreamservers(upstreams_list: List[Dict]) -> tuple:
        """Store L7 dynamic upstream servers in Redis under key 'upstreamservers'.

        upstreams_list must be a list of { "ip_port": str, "description": str }.
        Consumed by resty.upstream_redis (OpenResty). Returns (True, None) on success.
        """
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                upstreams_list,
                ensure_ascii=False,
                separators=(",", ":")
            )
            rcli.set(RedisClient.UPSTREAMSERVERS_KEY, value)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_upstreamservers() -> List[Dict]:
        """Retrieve L7 upstream servers list from Redis."""
        try:
            rcli = RedisClient.get_client()
            val = rcli.get(RedisClient.UPSTREAMSERVERS_KEY)
            if not val:
                return []
            return json.loads(val)
        except Exception:
            return []

    CACHERULES_KEY = "cacherules"

    @staticmethod
    def store_cacherules(rules_list: List[Dict]) -> tuple:
        """Store L7 cache rules in Redis under key 'cacherules'.

        Consumed by resty.cache_manager (OpenResty). Returns (True, None) on success.
        """
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                rules_list,
                ensure_ascii=False,
                separators=(",", ":")
            )
            rcli.set(RedisClient.CACHERULES_KEY, value)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_cacherules() -> List[Dict]:
        """Retrieve L7 cache rules list from Redis."""
        try:
            rcli = RedisClient.get_client()
            val = rcli.get(RedisClient.CACHERULES_KEY)
            if not val:
                return []
            return json.loads(val)
        except Exception:
            return []

    # -----------------------------
    # Temporary blacklist helpers
    # -----------------------------

    TEMPORARYBLACKLIST_PREFIX = "temporaryblacklist:"

    @staticmethod
    def parse_blocked_at(raw) -> int:
        """Parse blocked_at as epoch seconds (int or ISO-8601)."""
        if raw is None or raw == "":
            return 0
        if isinstance(raw, bool):
            return 0
        if isinstance(raw, (int, float)):
            ts = int(raw)
            return ts if ts > 0 else 0
        s = str(raw).strip()
        if not s:
            return 0
        if s.isdigit():
            return int(s)
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            return int(dt.timestamp())
        except Exception:
            return 0

    @staticmethod
    def parse_optional_site_id(raw) -> Optional[int]:
        if raw is None or raw == "":
            return None
        try:
            site_id = int(raw)
        except (TypeError, ValueError):
            return None
        return site_id if site_id > 0 else None

    @staticmethod
    def clear_temporaryblacklist() -> None:
        """Delete all temporaryblacklist:* keys from Redis."""
        rcli = RedisClient.get_client()
        cursor: str = "0"
        pattern = RedisClient.TEMPORARYBLACKLIST_PREFIX + "*"
        while True:
            cursor, keys = rcli.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                # delete in batches
                rcli.delete(*keys)
            if cursor == 0 or cursor == "0":
                break

    @staticmethod
    def store_temporaryblacklist(entries: List[Dict]) -> tuple:
        """
        Store temporary blacklist entries as individual keys with proper TTL.

        Each entry is written as:
          key:   temporaryblacklist:<ip>:<blocked_at>[:<site_id>]
          value: JSON { ip, url, country, city, blocked_at, ttl, trigger_rule, site_id }

        Redis TTL is computed as: blocked_at + ttl - now_epoch().
        Expired entries (TTL <= 0) are skipped.
        No publish is done here, so api_parser will NOT notify backend again.
        """
        try:
            rcli = RedisClient.get_client()
            now_ts = int(time.time())
            pipe = rcli.pipeline()

            for e in entries or []:
                if not isinstance(e, dict):
                    continue
                ip = (e.get("ip") or "").strip()
                if not ip:
                    continue
                blocked_at = RedisClient.parse_blocked_at(e.get("blocked_at"))
                try:
                    ttl_val = int(e.get("ttl", 0))
                except (TypeError, ValueError):
                    continue
                if blocked_at <= 0 or ttl_val <= 0:
                    continue

                remaining = blocked_at + ttl_val - now_ts
                if remaining <= 0:
                    # Already expired according to backend timing; skip
                    continue

                site_id = RedisClient.parse_optional_site_id(
                    e.get("site_id") if e.get("site_id") is not None else e.get("siteId")
                )
                key = f"{RedisClient.TEMPORARYBLACKLIST_PREFIX}{ip}:{blocked_at}"
                if site_id is not None:
                    key = f"{key}:{site_id}"
                value_obj = {
                    "ip": ip,
                    "url": e.get("url", "") or "",
                    "country": e.get("country", "") or "",
                    "city": e.get("city", "") or "",
                    "blocked_at": str(blocked_at),
                    "ttl": ttl_val,
                    "trigger_rule": e.get("trigger_rule", "") or "",
                }
                if site_id is not None:
                    value_obj["site_id"] = site_id
                value = json.dumps(value_obj, ensure_ascii=False, separators=(",", ":")).replace("\\/", "/")
                pipe.set(key, value)
                pipe.expire(key, remaining)

            pipe.execute()
            return True, None
        except Exception as e:
            return False, str(e)

    # -----------------------------
    # Per-site L7 config (l7_update_site)
    # -----------------------------

    WAF_RULE_TYPES = (
        "whitelist",
        "blacklist",
        "geo",
        "anticc",
        "antiheader",
        "intervalfreqlimit",
        "secondfreqlimit",
        "responsefreq",
        "useragent",
    )

    @staticmethod
    def store_domain_mapping(domain: str, site_id: int) -> tuple:
        """Store domain -> site_id mapping under key 'domain:{domain}'."""
        try:
            rcli = RedisClient.get_client()
            rcli.set(f"domain:{domain}", str(site_id))
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_domains_for_site(site_id: int) -> list:
        """Return hostnames whose domain:{host} value equals site_id."""
        try:
            rcli = RedisClient.get_client()
            site_id_str = str(site_id)
            domains = []
            cursor = "0"
            while True:
                cursor, keys = rcli.scan(cursor=cursor, match="domain:*", count=100)
                for key in keys or []:
                    try:
                        val = rcli.get(key)
                    except Exception:
                        continue
                    if val is None or str(val).strip() != site_id_str:
                        continue
                    domain = key.split(":", 1)[-1] if isinstance(key, str) else ""
                    if domain:
                        domains.append(domain)
                if cursor == 0 or cursor == "0":
                    break
            return domains
        except Exception:
            return []

    @staticmethod
    def rename_site_domain(site_id: int, old_domain: str, new_domain: str) -> tuple:
        """Retarget site domain mapping from old_domain to new_domain.

        - SET domain:{new_domain} -> site_id
        - DELETE domain:{old_domain} when it differs from new_domain
        - DELETE any other domain:* keys that currently map to this site_id

        Site-scoped keys (waf:{site_id}:*, cache:{site_id}, ...) stay unchanged.
        Returns (True, details_dict) on success, (False, error_message) on failure.
        """
        try:
            rcli = RedisClient.get_client()
            old_domain = (old_domain or "").strip()
            new_domain = (new_domain or "").strip()
            if not new_domain:
                return False, "new_domain is empty"

            new_key = f"domain:{new_domain}"
            old_key = f"domain:{old_domain}" if old_domain else ""
            site_id_str = str(site_id)
            removed = []

            pipe = rcli.pipeline()
            pipe.set(new_key, site_id_str)

            if old_key and old_key != new_key:
                pipe.delete(old_key)
                removed.append(old_key)

            # Drop leftover domain mappings for this site (stale hostnames).
            cursor = "0"
            while True:
                cursor, keys = rcli.scan(cursor=cursor, match="domain:*", count=100)
                for key in keys or []:
                    if key == new_key or key in removed:
                        continue
                    try:
                        val = rcli.get(key)
                    except Exception:
                        continue
                    if val is None:
                        continue
                    if str(val).strip() == site_id_str:
                        pipe.delete(key)
                        removed.append(key)
                if cursor == 0 or cursor == "0":
                    break

            pipe.execute()
            return True, {
                "newKey": new_key,
                "removedKeys": removed,
            }
        except Exception as e:
            return False, str(e)

    @staticmethod
    def store_site_waf_rules(site_id: int, rule_type: str, payload: Dict) -> tuple:
        """Store site-scoped WAF rules under key 'waf:{site_id}:{rule_type}'.

        payload must have: id (int), rules (list of {action, priority, rule}).
        Publishes acl:updates with the Redis key on success.
        """
        try:
            key = f"waf:{site_id}:{rule_type}"
            rcli = RedisClient.get_client()
            value = json.dumps(
                payload,
                ensure_ascii=False,
                indent=2
            ).replace("\\/", "/")
            rcli.set(key, value)
            rcli.publish("acl:updates", key)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def store_site_cache(site_id: int, rules_list: List[Dict]) -> tuple:
        """Store site-scoped cache rules under key 'cache:{site_id}'."""
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                rules_list,
                ensure_ascii=False,
                separators=(",", ":")
            )
            rcli.set(f"cache:{site_id}", value)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def store_site_listening(site_id: int, ports_payload: Any) -> tuple:
        """Store site-scoped listening ports under key 'listening:{site_id}'.

        ports_payload is { http_ports: [...], https_ports: [...] } (or a legacy list).
        """
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                ports_payload,
                ensure_ascii=False,
                separators=(",", ":")
            )
            rcli.set(f"listening:{site_id}", value)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def store_site_upstreamservers(site_id: int, upstreams_list: List[Dict]) -> tuple:
        """Store site-scoped upstream servers under key 'upstreamservers:{site_id}'."""
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                upstreams_list,
                ensure_ascii=False,
                separators=(",", ":")
            )
            rcli.set(f"upstreamservers:{site_id}", value)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def store_site_compress(site_id: int, compress_flags: Dict) -> tuple:
        """Store site-scoped compress settings under key 'compress:{site_id}'."""
        try:
            rcli = RedisClient.get_client()
            value = json.dumps(
                compress_flags,
                ensure_ascii=False,
                separators=(",", ":")
            )
            rcli.set(f"compress:{site_id}", value)
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def _scan_keys(rcli, pattern: str) -> list:
        found = []
        cursor = "0"
        while True:
            cursor, keys = rcli.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                found.extend(keys)
            if cursor == 0 or cursor == "0":
                break
        return found

    @staticmethod
    def delete_site_config(site_id: int, domain: str = "") -> tuple:
        """Delete all per-site L7 Redis keys for a site.

        Removes:
          domain:{domain} and any other domain:* mapping to this site_id
          waf:{site_id}:* (whitelist, blacklist, geo, ...)
          cache:{site_id}
          listening:{site_id}
          upstreamservers:{site_id}
          compress:{site_id}

        Publishes acl:updates for each deleted WAF key so OpenResty can reload.
        Returns (True, deleted_keys_list) on success, (False, error_message) on failure.
        """
        try:
            rcli = RedisClient.get_client()
            site_id_str = str(site_id)
            keys_to_delete = set()

            domain = (domain or "").strip()
            if domain:
                keys_to_delete.add(f"domain:{domain}")

            for key in RedisClient._scan_keys(rcli, "domain:*"):
                try:
                    val = rcli.get(key)
                except Exception:
                    continue
                if val is not None and str(val).strip() == site_id_str:
                    keys_to_delete.add(key)

            for rule_type in RedisClient.WAF_RULE_TYPES:
                keys_to_delete.add(f"waf:{site_id}:{rule_type}")
            for key in RedisClient._scan_keys(rcli, f"waf:{site_id}:*"):
                keys_to_delete.add(key)

            for prefix in ("cache", "listening", "upstreamservers", "compress"):
                keys_to_delete.add(f"{prefix}:{site_id}")

            deleted = []
            pipe = rcli.pipeline()
            for key in sorted(keys_to_delete):
                pipe.delete(key)
                deleted.append(key)
                if isinstance(key, str) and key.startswith(f"waf:{site_id}:"):
                    rule_type = key.split(":", 2)[-1]
                    pipe.publish("acl:updates", f"waf_deleted:{site_id}:{rule_type}")
            if deleted:
                pipe.execute()
            return True, deleted
        except Exception as e:
            return False, str(e)

