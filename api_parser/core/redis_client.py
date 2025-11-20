# core/redis_client.py
"""Redis client operations for ACL rules."""
import redis
import json
from typing import List, Dict
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

