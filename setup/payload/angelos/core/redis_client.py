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

    @staticmethod
    def get_all_upstreamservers() -> List[Dict]:
        """All upstream server entries from global + site-scoped Redis keys.

        Keys: ``upstreamservers`` and ``upstreamservers:{site_id}``.
        Each entry is typically ``{ "ip_port": "...", "description": "..." }``.
        """
        entries: List[Dict] = []
        try:
            rcli = RedisClient.get_client()
            global_list = RedisClient.get_upstreamservers()
            if isinstance(global_list, list):
                entries.extend(e for e in global_list if isinstance(e, dict))

            cursor: str = "0"
            pattern = f"{RedisClient.UPSTREAMSERVERS_KEY}:*"
            while True:
                cursor, keys = rcli.scan(cursor=cursor, match=pattern, count=100)
                for key in keys or []:
                    try:
                        val = rcli.get(key)
                        if not val:
                            continue
                        parsed = json.loads(val)
                        if isinstance(parsed, list):
                            entries.extend(e for e in parsed if isinstance(e, dict))
                    except Exception:
                        continue
                if cursor == 0 or cursor == "0":
                    break
        except Exception:
            return entries
        return entries

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
    def _temporaryblacklist_entry_key(ip: str, blocked_at: int, site_id: Optional[int]) -> str:
        key = f"{RedisClient.TEMPORARYBLACKLIST_PREFIX}{ip}:{blocked_at}"
        if site_id is not None:
            key = f"{key}:{site_id}"
        return key

    @staticmethod
    def _prepare_temporaryblacklist_writes(entries: List[Dict], now_ts: Optional[int] = None):
        """Return (desired_keys:set, writes:list[(key, json, remaining_ttl)])."""
        now_ts = int(time.time()) if now_ts is None else int(now_ts)
        desired = set()
        writes = []
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
                continue
            site_id = RedisClient.parse_optional_site_id(
                e.get("site_id") if e.get("site_id") is not None else e.get("siteId")
            )
            key = RedisClient._temporaryblacklist_entry_key(ip, blocked_at, site_id)
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
            desired.add(key)
            writes.append((key, value, remaining))
        return desired, writes

    @staticmethod
    def clear_temporaryblacklist() -> None:
        """Delete all temporaryblacklist:* keys from Redis (key names only)."""
        rcli = RedisClient.get_client()
        pattern = RedisClient.TEMPORARYBLACKLIST_PREFIX + "*"
        batch = []
        for key in RedisClient._scan_keys(rcli, pattern):
            batch.append(key)
            if len(batch) >= 500:
                rcli.unlink(*batch)
                batch = []
        if batch:
            rcli.unlink(*batch)

    @staticmethod
    def store_temporaryblacklist(entries: List[Dict]) -> tuple:
        """
        Store temporary blacklist entries as individual keys with proper TTL.

        Prefer replace_temporaryblacklist() for panel full-sync (avoids a blank
        window and does not SCAN+GET every existing value).
        """
        try:
            rcli = RedisClient.get_client()
            _, writes = RedisClient._prepare_temporaryblacklist_writes(entries)
            if not writes:
                return True, None
            pipe = rcli.pipeline(transaction=False)
            for key, value, remaining in writes:
                pipe.set(key, value)
                pipe.expire(key, remaining)
            pipe.execute()
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def replace_temporaryblacklist(entries: List[Dict]) -> tuple:
        """
        Full replace used by l7_update_temporaryblacklist (panel → edge sync).

        Previous path: SCAN + GET every temporaryblacklist:* value, clear all,
        then rewrite. With thousands of L4 rows that dominated each sync.

        New path:
          1) Pipeline SET/EXPIRE the desired keys (no prior read).
          2) SCAN key *names* only; delete keys not in the desired set.
          3) GET only obsolete keys to decide L4 CLEAR_BLOCK_IP.

        Returns (ok, err, meta) where meta includes written/deleted/l4_cleared.
        No publish — panel already owns this set.
        """
        meta = {"written": 0, "deleted": 0, "l4_cleared": 0, "skipped_expired": 0}
        try:
            rcli = RedisClient.get_client()
            desired, writes = RedisClient._prepare_temporaryblacklist_writes(entries)
            meta["skipped_expired"] = max(0, len(entries or []) - len(writes))

            # 1) Upsert desired keys first so the list never goes empty mid-sync.
            if writes:
                pipe = rcli.pipeline(transaction=False)
                for key, value, remaining in writes:
                    pipe.set(key, value)
                    pipe.expire(key, remaining)
                pipe.execute()
                meta["written"] = len(writes)

            # 2) Key-name SCAN only — find obsolete keys without GETting keepers.
            obsolete = []
            pattern = RedisClient.TEMPORARYBLACKLIST_PREFIX + "*"
            for key in RedisClient._scan_keys(rcli, pattern):
                if key not in desired:
                    obsolete.append(key)

            # 3) GET obsolete values only (for L4 clear), then UNLINK.
            l4_ips_to_clear = set()
            if obsolete:
                # MGET in chunks
                chunk = 200
                for i in range(0, len(obsolete), chunk):
                    part = obsolete[i : i + chunk]
                    values = rcli.mget(part)
                    for key, raw in zip(part, values or []):
                        if not raw:
                            continue
                        try:
                            obj = json.loads(raw)
                        except Exception:
                            continue
                        if not isinstance(obj, dict):
                            continue
                        trig = str(obj.get("trigger_rule", "")).strip().lower()
                        ip = str(obj.get("ip", "")).strip()
                        if trig == "l4ddos" and ip:
                            l4_ips_to_clear.add(ip)
                    try:
                        rcli.unlink(*part)
                    except Exception:
                        rcli.delete(*part)
                    meta["deleted"] += len(part)

            meta["l4_cleared_ips"] = sorted(l4_ips_to_clear)
            meta["l4_cleared"] = len(l4_ips_to_clear)
            return True, None, meta
        except Exception as e:
            return False, str(e), meta

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
            pipe.set(f"site:{site_id}:domain", new_domain)

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

    EDGE_LISTENINGPORTS_KEY = "listeningports"

    @staticmethod
    def store_edge_listeningports(ports_list: List[Dict]) -> tuple:
        """Store server-scoped (edge-wide) nginx listen ports under 'listeningports'.

        Value is a JSON array of port objects, e.g.
          [{ id, serverId, port, protocol, description, status }, ...]

        Publishes listeningports:updates after write.
        """
        try:
            if not isinstance(ports_list, list):
                return False, "listeningports must be an array"
            rcli = RedisClient.get_client()
            value = json.dumps(ports_list, ensure_ascii=False, separators=(",", ":"))
            pipe = rcli.pipeline()
            pipe.set(RedisClient.EDGE_LISTENINGPORTS_KEY, value)
            pipe.publish("listeningports:updates", RedisClient.EDGE_LISTENINGPORTS_KEY)
            pipe.execute()
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_edge_listeningports() -> List[Dict]:
        """Load server-scoped listening ports from Redis key 'listeningports'."""
        try:
            rcli = RedisClient.get_client()
            raw = rcli.get(RedisClient.EDGE_LISTENINGPORTS_KEY)
            if not raw:
                return []
            obj = json.loads(raw)
            return obj if isinstance(obj, list) else []
        except Exception:
            return []

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
    def store_site_ssl(site_id: int, domain: str, ssl_payload: Dict) -> tuple:
        """Store site SSL material under ssl:{site_id} for OpenResty SNI.

        ssl_payload fields: ssl_type, ssl_cert (PEM), ssl_cert_key (PEM).
        When ssl_type is "none" (HTTP-only site), stores an empty marker so Athens
        refuses HTTPS for this SNI instead of falling back to the default cert.
        Also stores site:{site_id}:domain for reverse lookup.
        Publishes ssl:updates with ssl:{site_id} so workers can invalidate caches.
        """
        try:
            if not isinstance(ssl_payload, dict):
                return False, "ssl payload must be object"

            ssl_type = str(
                ssl_payload.get("ssl_type") or ssl_payload.get("sslType") or ""
            ).strip()
            ssl_type_norm = ssl_type.lower()

            ssl_cert = ssl_payload.get("ssl_cert") or ssl_payload.get("sslCert") or ""
            ssl_cert_key = (
                ssl_payload.get("ssl_cert_key")
                or ssl_payload.get("sslCertKey")
                or ssl_payload.get("ssl_key")
                or ""
            )
            if not isinstance(ssl_cert, str):
                ssl_cert = str(ssl_cert or "")
            if not isinstance(ssl_cert_key, str):
                ssl_cert_key = str(ssl_cert_key or "")

            ssl_cert = ssl_cert.replace("\\n", "\n").strip()
            ssl_cert_key = ssl_cert_key.replace("\\n", "\n").strip()

            if ssl_type_norm == "none":
                ssl_type = "none"
                ssl_cert = ""
                ssl_cert_key = ""
            elif not ssl_cert or not ssl_cert_key:
                return False, "ssl_cert and ssl_cert_key are required unless ssl_type is none"

            value_obj = {
                "site_id": int(site_id),
                "domain": (domain or "").strip(),
                "ssl_type": ssl_type,
                "ssl_cert": ssl_cert,
                "ssl_cert_key": ssl_cert_key,
            }
            rcli = RedisClient.get_client()
            key = f"ssl:{site_id}"
            value = json.dumps(value_obj, ensure_ascii=False, separators=(",", ":"))
            pipe = rcli.pipeline()
            pipe.set(key, value)
            if domain:
                pipe.set(f"site:{site_id}:domain", str(domain).strip())
            pipe.publish("ssl:updates", key)
            pipe.execute()
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def delete_site_ssl(site_id: int) -> tuple:
        """Remove ssl:{site_id} and publish ssl:updates (ssl_deleted:{site_id})."""
        try:
            rcli = RedisClient.get_client()
            key = f"ssl:{site_id}"
            pipe = rcli.pipeline()
            pipe.delete(key)
            pipe.publish("ssl:updates", f"ssl_deleted:{site_id}")
            pipe.execute()
            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def store_site_domain(site_id: int, domain: str) -> tuple:
        """Store site:{site_id}:domain and domain:{domain} -> site_id."""
        try:
            domain = (domain or "").strip()
            if not domain:
                return False, "domain is empty"
            rcli = RedisClient.get_client()
            pipe = rcli.pipeline()
            pipe.set(f"domain:{domain}", str(site_id))
            pipe.set(f"site:{site_id}:domain", domain)
            pipe.execute()
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

            for prefix in ("cache", "listening", "upstreamservers", "compress", "ssl"):
                keys_to_delete.add(f"{prefix}:{site_id}")
            keys_to_delete.add(f"site:{site_id}:domain")

            deleted = []
            pipe = rcli.pipeline()
            for key in sorted(keys_to_delete):
                pipe.delete(key)
                deleted.append(key)
                if isinstance(key, str) and key.startswith(f"waf:{site_id}:"):
                    rule_type = key.split(":", 2)[-1]
                    pipe.publish("acl:updates", f"waf_deleted:{site_id}:{rule_type}")
                elif isinstance(key, str) and key.startswith("ssl:"):
                    pipe.publish("ssl:updates", f"ssl_deleted:{site_id}")
            if deleted:
                pipe.execute()
            return True, deleted
        except Exception as e:
            return False, str(e)

    @staticmethod
    def _get_json_key(rcli, key: str):
        """GET key and json.loads; return None if missing/invalid."""
        try:
            val = rcli.get(key)
        except Exception:
            return None
        if val is None or val == "":
            return None
        try:
            return json.loads(val)
        except Exception:
            return None

    @staticmethod
    def get_all_temporaryblacklist() -> List[Dict]:
        """SCAN temporaryblacklist:* and return parsed entry dicts."""
        entries: List[Dict] = []
        try:
            rcli = RedisClient.get_client()
            for key in RedisClient._scan_keys(rcli, RedisClient.TEMPORARYBLACKLIST_PREFIX + "*"):
                parsed = RedisClient._get_json_key(rcli, key)
                if isinstance(parsed, dict):
                    entry = dict(parsed)
                    entry["_redis_key"] = key if isinstance(key, str) else str(key)
                    try:
                        ttl = rcli.ttl(key)
                        entry["_ttl_remaining"] = int(ttl) if ttl is not None else -1
                    except Exception:
                        entry["_ttl_remaining"] = -1
                    entries.append(entry)
        except Exception:
            return entries
        return entries

    @staticmethod
    def dump_l7_configure(include_ssl_pems: bool = False) -> Dict:
        """
        Snapshot L7 configure state from Redis for edge→backend sync.

        Returns:
          {
            "edge": { listeningports, temporaryblacklist, acl_rules, acl_apply_rules, legacy_global },
            "sites": { "<site_id>": { domain, domains, waf, cache, listening, upstreamservers, compress, ssl } },
            "meta": { site_count, temporaryblacklist_count }
          }
        """
        rcli = RedisClient.get_client()
        sites: Dict[str, Dict] = {}

        def _site(sid: str) -> Dict:
            if sid not in sites:
                sites[sid] = {
                    "domain": "",
                    "domains": [],
                    "waf": {},
                    "cache": [],
                    "listening": {},
                    "upstreamservers": [],
                    "compress": {},
                    "ssl": {},
                }
            return sites[sid]

        # domain:{host} -> site_id
        for key in RedisClient._scan_keys(rcli, "domain:*"):
            try:
                host = key.split(":", 1)[1] if isinstance(key, str) and ":" in key else ""
                val = rcli.get(key)
            except Exception:
                continue
            if not host or val is None:
                continue
            sid = str(val).strip()
            if not sid:
                continue
            bucket = _site(sid)
            if host not in bucket["domains"]:
                bucket["domains"].append(host)

        # site:{id}:domain primary hostname
        for key in RedisClient._scan_keys(rcli, "site:*:domain"):
            parts = key.split(":") if isinstance(key, str) else []
            if len(parts) != 3 or parts[0] != "site" or parts[2] != "domain":
                continue
            sid = parts[1]
            try:
                domain = rcli.get(key)
            except Exception:
                continue
            if domain:
                _site(sid)["domain"] = str(domain).strip()

        # waf:{site_id}:{rule_type}
        for key in RedisClient._scan_keys(rcli, "waf:*"):
            parts = key.split(":") if isinstance(key, str) else []
            if len(parts) < 3:
                continue
            sid, rule_type = parts[1], parts[2]
            parsed = RedisClient._get_json_key(rcli, key)
            if parsed is not None:
                _site(sid)["waf"][rule_type] = parsed

        # cache / listening / upstreamservers / compress / ssl
        for prefix, field in (
            ("cache", "cache"),
            ("listening", "listening"),
            ("upstreamservers", "upstreamservers"),
            ("compress", "compress"),
            ("ssl", "ssl"),
        ):
            for key in RedisClient._scan_keys(rcli, f"{prefix}:*"):
                parts = key.split(":") if isinstance(key, str) else []
                if len(parts) != 2:
                    continue
                sid = parts[1]
                parsed = RedisClient._get_json_key(rcli, key)
                if parsed is None:
                    continue
                if field == "ssl" and isinstance(parsed, dict) and not include_ssl_pems:
                    cert = parsed.get("ssl_cert") or ""
                    key_pem = parsed.get("ssl_cert_key") or ""
                    parsed = {
                        "site_id": parsed.get("site_id"),
                        "domain": parsed.get("domain") or "",
                        "ssl_type": parsed.get("ssl_type") or "",
                        "ssl_cert_present": bool(str(cert).strip()),
                        "ssl_cert_key_present": bool(str(key_pem).strip()),
                        "ssl_cert_len": len(str(cert)),
                        "ssl_cert_key_len": len(str(key_pem)),
                    }
                _site(sid)[field] = parsed

        # Fill primary domain from domains list when missing, and normalize
        # types the panel schema expects (object vs array). Bad Redis values
        # like listening:[] make /report_edge_configure return 400.
        for sid, bucket in sites.items():
            domains_list = bucket.get("domains")
            if not isinstance(domains_list, list):
                domains_list = []
            domains_sorted = list(domains_list)
            domains_sorted.sort()
            if not bucket.get("domain") and domains_sorted:
                bucket["domain"] = domains_sorted[0]
            bucket["domains"] = domains_sorted

            for obj_field in ("waf", "listening", "compress", "ssl"):
                val = bucket.get(obj_field)
                if not isinstance(val, dict):
                    bucket[obj_field] = {}
            for arr_field in ("cache", "upstreamservers"):
                val = bucket.get(arr_field)
                if not isinstance(val, list):
                    bucket[arr_field] = []
            if not isinstance(bucket.get("domain"), str):
                bucket["domain"] = str(bucket.get("domain") or "")

        edge = {
            "listeningports": RedisClient.get_edge_listeningports(),
            "temporaryblacklist": RedisClient.get_all_temporaryblacklist(),
            "acl_rules": RedisClient.get_acl_rules(),
            "acl_apply_rules": RedisClient.get_acl_apply_rules(),
            "legacy_global": {
                "whitelist": RedisClient.get_whitelist(),
                "blacklist": RedisClient.get_blacklist(),
                "geo": RedisClient.get_geo(),
                "antiheader": RedisClient.get_antiheader(),
                "intervalfreqlimit": RedisClient.get_intervalfreqlimit(),
                "secondfreqlimit": RedisClient.get_secondfreqlimit(),
                "responsefreq": RedisClient.get_responsefreq(),
                "useragent": RedisClient.get_useragent(),
                "upstreamservers": RedisClient.get_upstreamservers(),
                "cacherules": RedisClient.get_cacherules(),
            },
        }

        return {
            "edge": edge,
            "sites": sites,
            "meta": {
                "site_count": len(sites),
                "temporaryblacklist_count": len(edge["temporaryblacklist"]),
            },
        }

