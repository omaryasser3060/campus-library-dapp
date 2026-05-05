import json
import os
import sys
from web3 import Web3
from web3.exceptions import ContractLogicError

GANACHE_URL = "http://127.0.0.1:7545"
CONFIG_FILE = "../config.json"

PASS_LABEL = "PASS"
FAIL_LABEL = "FAIL"


def load_config():
    if not os.path.exists(CONFIG_FILE):
        print("ERROR: config.json not found. Run auto_setup.py first.")
        sys.exit(1)
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


def connect():
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    if not w3.is_connected():
        print("ERROR: Cannot connect to Ganache.")
        sys.exit(1)
    return w3


def get_contracts(w3, config):
    coin = w3.eth.contract(
        address=config["coin"]["address"],
        abi=config["coin"]["abi"]
    )
    registry = w3.eth.contract(
        address=config["registry"]["address"],
        abi=config["registry"]["abi"]
    )
    return coin, registry


def print_result(test_name, passed, detail=""):
    label = PASS_LABEL if passed else FAIL_LABEL
    line = f"  [{label}] {test_name}"
    if detail:
        line += f" -- {detail}"
    print(line)


def test_non_admin_blocked_from_adding_book(w3, registry):
    print("\nTest 1: Normal user cannot add a book (onlyOwner enforcement)")

    accounts = w3.eth.accounts
    admin = registry.functions.getAdmin().call()
    non_admin = None
    for acc in accounts:
        if acc.lower() != admin.lower():
            non_admin = acc
            break

    if non_admin is None:
        print_result("Test 1", False, "Could not find a non-admin account in Ganache")
        return False

    rejected = False
    try:
        # Updated to match the new addBook signature
        registry.functions.addBook(
            "Malicious Book", "Hacker", 0, "dummyImgHash", "dummyPdfHash", [86400], [0]
        ).transact({
            "from": non_admin,
            "gas": 300000
        })
    except Exception as e:
        error_msg = str(e).lower()
        if "revert" in error_msg or "caller is not the admin" in error_msg or "execution reverted" in error_msg:
            rejected = True
        else:
            print_result("Test 1 - Non-admin addBook", False, f"Unexpected error: {e}")
            return False

    print_result(
        "Non-admin addBook is rejected by the contract",
        rejected,
        f"non-admin={non_admin}"
    )
    return rejected


def test_non_admin_blocked_from_updating_book(w3, registry):
    print("\nTest 2: Normal user cannot update a book (onlyOwner enforcement)")

    accounts = w3.eth.accounts
    admin = registry.functions.getAdmin().call()
    non_admin = None
    for acc in accounts:
        if acc.lower() != admin.lower():
            non_admin = acc
            break

    if non_admin is None:
        print_result("Test 2", False, "Could not find a non-admin account in Ganache")
        return False

    rejected = False
    try:
        registry.functions.updateBook(
            1, "Hacked Title", "Hacker", 0, "dummyImgHash", "dummyPdfHash", [86400], [0]
        ).transact({
            "from": non_admin,
            "gas": 300000
        })
    except Exception as e:
        error_msg = str(e).lower()
        if "revert" in error_msg or "caller is not the admin" in error_msg or "execution reverted" in error_msg:
            rejected = True
        else:
            print_result("Test 2 - Non-admin updateBook", False, f"Unexpected error: {e}")
            return False

    print_result(
        "Non-admin updateBook is rejected by the contract",
        rejected,
        f"non-admin={non_admin}"
    )
    return rejected


def test_non_admin_blocked_from_toggling_status(w3, registry):
    print("\nTest 3: Normal user cannot toggle book existence (onlyOwner enforcement)")

    accounts = w3.eth.accounts
    admin = registry.functions.getAdmin().call()
    non_admin = None
    for acc in accounts:
        if acc.lower() != admin.lower():
            non_admin = acc
            break

    rejected = False
    try:
        registry.functions.toggleBookExistence(1).transact({
            "from": non_admin,
            "gas": 150000
        })
    except Exception as e:
        error_msg = str(e).lower()
        if "revert" in error_msg or "caller is not the admin" in error_msg or "execution reverted" in error_msg:
            rejected = True

    print_result(
        "Non-admin toggleBookExistence is rejected by the contract",
        rejected,
        f"non-admin={non_admin}"
    )
    return rejected


def test_ownership_transfer_security(w3, registry, coin):
    print("\nTest 4: Ownership transfer - old admin loses rights, new admin gains them")

    accounts = w3.eth.accounts
    original_admin = registry.functions.getAdmin().call()

    new_admin = None
    for acc in accounts:
        if acc.lower() != original_admin.lower():
            new_admin = acc
            break

    if new_admin is None:
        print_result("Test 4", False, "Could not find a second account for new admin")
        return False

    passed_overall = True

    try:
        tx_hash = registry.functions.addBook(
            "Pre-Transfer Book", "Original Admin", 0, "img", "pdf", [86400], [0]
        ).transact({
            "from": original_admin,
            "gas": 400000
        })
        w3.eth.wait_for_transaction_receipt(tx_hash)
        step1_passed = True
        print_result("Step 4a - Original admin adds a book before transfer", True)
    except Exception as e:
        passed_overall = False
        print_result("Step 4a - Original admin adds a book before transfer", False, str(e))

    try:
        # Transfer ownership for both contracts
        tx_hash_coin = coin.functions.transferOwnership(new_admin).transact({
            "from": original_admin,
            "gas": 100000
        })
        w3.eth.wait_for_transaction_receipt(tx_hash_coin)

        tx_hash_reg = registry.functions.transferOwnership(new_admin).transact({
            "from": original_admin,
            "gas": 100000
        })
        w3.eth.wait_for_transaction_receipt(tx_hash_reg)

        actual_admin_after = registry.functions.getAdmin().call()
        actual_coin_admin_after = coin.functions.admin().call()

        transfer_confirmed = (actual_admin_after.lower() == new_admin.lower() and
                              actual_coin_admin_after.lower() == new_admin.lower())
        print_result("Step 4b - Ownership transferred to new admin for BOTH contracts", transfer_confirmed)
        if not transfer_confirmed:
            passed_overall = False
    except Exception as e:
        passed_overall = False
        print_result("Step 4b - transferOwnership call", False, str(e))
        return False

    old_admin_blocked = False
    try:
        registry.functions.addBook(
            "Should Fail", "Old Admin", 0, "img", "pdf", [86400], [0]
        ).transact({
            "from": original_admin,
            "gas": 400000
        })
    except Exception as e:
        error_msg = str(e).lower()
        if "revert" in error_msg or "caller is not the admin" in error_msg or "execution reverted" in error_msg:
            old_admin_blocked = True
    print_result("Step 4c - Original admin is now blocked from admin actions", old_admin_blocked)
    if not old_admin_blocked:
        passed_overall = False

    new_admin_works = False
    try:
        tx_hash = registry.functions.addBook(
            "Post-Transfer Book", "New Admin", 0, "img", "pdf", [86400], [0]
        ).transact({
            "from": new_admin,
            "gas": 400000
        })
        w3.eth.wait_for_transaction_receipt(tx_hash)
        new_admin_works = True
    except Exception as e:
        print_result("Step 4d - New admin can add a book", False, str(e))
    print_result("Step 4d - New admin can successfully add a book", new_admin_works)
    if not new_admin_works:
        passed_overall = False

    # Cleanup: Restore original admin
    try:
        tx_hash_coin = coin.functions.transferOwnership(original_admin).transact({
            "from": new_admin,
            "gas": 100000
        })
        w3.eth.wait_for_transaction_receipt(tx_hash_coin)

        tx_hash_reg = registry.functions.transferOwnership(original_admin).transact({
            "from": new_admin,
            "gas": 100000
        })
        w3.eth.wait_for_transaction_receipt(tx_hash_reg)
        print_result("Step 4e - Ownership restored to original admin", True)
    except Exception as e:
        print_result("Step 4e - Restoring ownership (cleanup)", False, str(e))

    return passed_overall


def test_non_admin_blocked_from_minting(w3, coin):
    print("\nTest 5: Normal user cannot mint Library Coins")

    accounts = w3.eth.accounts
    admin = coin.functions.admin().call()
    non_admin = None
    for acc in accounts:
        if acc.lower() != admin.lower():
            non_admin = acc
            break

    if non_admin is None:
        print_result("Test 5", False, "No non-admin account available")
        return False

    rejected = False
    try:
        coin.functions.mint(non_admin, w3.to_wei(10, "ether")).transact({
            "from": non_admin,
            "gas": 100000
        })
    except Exception as e:
        error_msg = str(e).lower()
        if "revert" in error_msg or "not the admin" in error_msg or "execution reverted" in error_msg:
            rejected = True

    print_result("Non-admin mint is rejected by LibraryCoin", rejected, f"non-admin={non_admin}")
    return rejected


def test_paused_contract_blocks_user_actions(w3, registry):
    print("\nTest 6: User actions are blocked when contract is paused")

    accounts = w3.eth.accounts
    admin = registry.functions.getAdmin().call()
    user = None
    for acc in accounts:
        if acc.lower() != admin.lower():
            user = acc
            break

    if user is None:
        print_result("Test 6", False, "No user account available")
        return False

    try:
        tx_hash = registry.functions.pause().transact({
            "from": admin,
            "gas": 100000
        })
        w3.eth.wait_for_transaction_receipt(tx_hash)
        print_result("Step 6a - Admin pauses contract", True)
    except Exception as e:
        print_result("Step 6a - Admin pauses contract", False, str(e))
        return False

    borrow_blocked = False
    try:
        # 86400 represents 1 Day, matching the new borrowBook signature
        registry.functions.borrowBook(1, 86400).transact({
            "from": user,
            "gas": 300000
        })
    except Exception as e:
        error_msg = str(e).lower()
        if "paused" in error_msg or "revert" in error_msg or "execution reverted" in error_msg:
            borrow_blocked = True
    print_result("Step 6b - borrowBook is blocked while paused", borrow_blocked)

    try:
        tx_hash = registry.functions.resume().transact({
            "from": admin,
            "gas": 100000
        })
        w3.eth.wait_for_transaction_receipt(tx_hash)
        print_result("Step 6c - Admin resumes contract", True)
    except Exception as e:
        print_result("Step 6c - Admin resumes contract", False, str(e))
        return borrow_blocked

    return borrow_blocked


def main():
    print("=== Security Test Suite - Campus Library DApp ===")

    config = load_config()
    w3 = connect()
    coin, registry = get_contracts(w3, config)

    results = []

    r1 = test_non_admin_blocked_from_adding_book(w3, registry)
    results.append(("Test 1 - Non-admin blocked from addBook", r1))

    r2 = test_non_admin_blocked_from_updating_book(w3, registry)
    results.append(("Test 2 - Non-admin blocked from updateBook", r2))

    r3 = test_non_admin_blocked_from_toggling_status(w3, registry)
    results.append(("Test 3 - Non-admin blocked from toggleBookExistence", r3))

    r4 = test_ownership_transfer_security(w3, registry, coin)
    results.append(("Test 4 - Ownership transfer security workflow (Dual)", r4))

    r5 = test_non_admin_blocked_from_minting(w3, coin)
    results.append(("Test 5 - Non-admin blocked from minting coins", r5))

    r6 = test_paused_contract_blocks_user_actions(w3, registry)
    results.append(("Test 6 - Paused contract blocks user actions", r6))

    print("\n" + "=" * 65)
    print("Summary")
    print("=" * 65)
    all_passed = True
    for test_name, passed in results:
        label = PASS_LABEL if passed else FAIL_LABEL
        print(f"  [{label}] {test_name}")
        if not passed:
            all_passed = False

    print("=" * 65)
    if all_passed:
        print("All tests passed.")
    else:
        print("Some tests failed. Review output above.")


if __name__ == "__main__":
    main()