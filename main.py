import hashlib
import json
import datetime

class AuditLogManager:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_hash(self, data):
        """Creates a SHA-256 hash of the given data."""
        # Ensure data is a string before encoding for consistent hashing
        if not isinstance(data, str):
            data = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def create_genesis_block(self):
        """Creates the first block (genesis block) in the chain."""
        genesis_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event": "System Initialized",
            "user": "SYSTEM",
            "details": "Audit log chain started."
        }
        genesis_block = {
            "index": 0,
            "timestamp": genesis_data["timestamp"],
            "event": genesis_data["event"],
            "user": genesis_data["user"],
            "details": genesis_data["details"],
            "previous_hash": "0" * 64 # Special hash for the first block, indicating no predecessor
        }
        # Calculate the hash for the genesis block based on its content
        genesis_block["current_hash"] = self.create_hash(json.dumps(genesis_block, sort_keys=True))
        self.chain.append(genesis_block)

    def add_log_entry(self, event, user, details):
        """Adds a new audit log entry to the chain, linking it to the previous one."""
        last_block = self.chain[-1]
        new_index = last_block["index"] + 1
        timestamp = datetime.datetime.now().isoformat()

        new_log_data = {
            "index": new_index,
            "timestamp": timestamp,
            "event": event,
            "user": user,
            "details": details,
            "previous_hash": last_block["current_hash"] # The core of the hash chain: link to previous block's hash
        }
        # Calculate the current hash for the new log entry based on its content and previous_hash
        new_log_data["current_hash"] = self.create_hash(json.dumps(new_log_data, sort_keys=True))
        self.chain.append(new_log_data)
        print(f"Added log entry {new_index}: {event}")

    def verify_chain_integrity(self):
        """Verifies the integrity of the entire hash chain by re-calculating hashes."""
        print("\nVerifying chain integrity...")
        is_valid = True
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            # 1. Recalculate the hash of the current block's content (excluding its own 'current_hash' field)
            # and compare it with the stored 'current_hash'.
            block_content_for_hash = {k: v for k, v in current_block.items() if k != "current_hash"}
            recalculated_hash = self.create_hash(json.dumps(block_content_for_hash, sort_keys=True))

            if recalculated_hash != current_block["current_hash"]:
                print(f"!!! Integrity check FAILED at block {current_block['index']} (Self Hash Mismatch) !!!")
                print(f"    Expected: {current_block['current_hash']}")
                print(f"    Got:      {recalculated_hash}")
                is_valid = False

            # 2. Check if the current block's 'previous_hash' correctly matches the 'current_hash' of the actual previous block.
            if current_block["previous_hash"] != previous_block["current_hash"]:
                print(f"!!! Integrity check FAILED at block {current_block['index']} (Previous Hash Link Mismatch) !!!")
                print(f"    Expected previous hash: {previous_block['current_hash']}")
                print(f"    Got previous hash:      {current_block['previous_hash']}")
                is_valid = False

        if is_valid:
            print("Chain integrity: OK")
        else:
            print("Chain integrity: BROKEN")
        return is_valid

    def print_chain(self):
        """Prints all entries in the audit log chain."""
        print("\n--- Audit Log Chain ---")
        for entry in self.chain:
            print(json.dumps(entry, indent=2))
        print("-----------------------")

# --- Demonstration ---
if __name__ == "__main__":
    log_manager = AuditLogManager()

    # Add some audit log entries
    log_manager.add_log_entry("User Login", "alice", "Successful login from IP 192.168.1.100")
    log_manager.add_log_entry("File Access", "bob", "Accessed 'report.pdf' in /documents")
    log_manager.add_log_entry("Configuration Change", "admin", "Updated system settings for 'email_service'")

    log_manager.print_chain()

    # Verify the initial chain (should pass)
    log_manager.verify_chain_integrity()

    # --- Simulate Tampering with Log Content ---
    print("\n--- Simulating Tampering with Log Content ---")
    # Let's try to change the details of the second log entry (index 2)
    # This change will invalidate the current_hash of block 2 and consequently the previous_hash link for block 3.
    tampered_block_index = 2
    if len(log_manager.chain) > tampered_block_index:
        original_details = log_manager.chain[tampered_block_index]["details"]
        log_manager.chain[tampered_block_index]["details"] = "Accessed 'malicious_file.exe' in /system (TAMPERED!)"
        print(f"Tampered with block {tampered_block_index}: Changed details from '{original_details}' to '{log_manager.chain[tampered_block_index]['details']}'")
    else:
        print(f"Cannot tamper with block {tampered_block_index}, it does not exist.")

    log_manager.print_chain()

    # Verify the tampered chain (should fail)
    log_manager.verify_chain_integrity()

    print("\n--- Simulating Tampering with a Block's Stored Hash (without changing content) ---")
    # Let's try to change only the current_hash of a block, without changing its content.
    # This should also be detected by the self-hash check.
    tampered_block_index_hash_only = 1
    if len(log_manager.chain) > tampered_block_index_hash_only:
        original_hash = log_manager.chain[tampered_block_index_hash_only]["current_hash"]
        log_manager.chain[tampered_block_index_hash_only]["current_hash"] = "a" * 64 # An obviously invalid hash
        print(f"Tampered with block {tampered_block_index_hash_only}: Changed current_hash from '{original_hash[:10]}...' to '{log_manager.chain[tampered_block_index_hash_only]['current_hash'][:10]}...' (Invalidating its own hash)")
    else:
        print(f"Cannot tamper with block {tampered_block_index_hash_only}, it does not exist.")

    log_manager.print_chain()
    log_manager.verify_chain_integrity()