from __future__ import annotations

from qr_blockchain import Blockchain, Wallet


def print_balances(blockchain: Blockchain, wallets: list[Wallet]) -> None:
    for wallet in wallets:
        print(f"{wallet.label:<10} balance: {wallet.balance(blockchain)}")


def main() -> None:
    alice = Wallet("Alice")
    bob = Wallet("Bob")
    miner = Wallet("Miner")

    alice_genesis_address = alice.create_address()
    miner_reward_address = miner.create_address()

    chain = Blockchain(difficulty=3, mining_reward=30)
    chain.create_genesis_block({alice_genesis_address: 120})

    print("Quantum-resistant blockchain prototype")
    print("-" * 44)
    print("Genesis created with 120 tokens assigned to Alice.")
    print_balances(chain, [alice, bob, miner])

    bob_receive_address = bob.create_address()
    alice_to_bob = alice.create_transaction(chain, bob_receive_address, 45)
    chain.add_transaction(alice_to_bob)

    print("\nAlice signs a Lamport transaction sending 45 tokens to Bob.")
    print(f"Pending transactions: {len(chain.pending_transactions)}")

    first_block = chain.mine_pending_transactions(miner_reward_address)
    print(f"\nBlock #{first_block.index} mined with hash {first_block.block_hash[:18]}...")
    print_balances(chain, [alice, bob, miner])

    alice_return_address = alice.create_address()
    bob_to_alice = bob.create_transaction(chain, alice_return_address, 10)
    chain.add_transaction(bob_to_alice)

    print("\nBob spends part of his output back to Alice using a fresh Lamport key.")
    second_block = chain.mine_pending_transactions(miner_reward_address)
    print(f"Block #{second_block.index} mined with hash {second_block.block_hash[:18]}...")
    print_balances(chain, [alice, bob, miner])

    print("\nChain summary:")
    for key, value in chain.summary().items():
        print(f"- {key}: {value}")


if __name__ == "__main__":
    main()
