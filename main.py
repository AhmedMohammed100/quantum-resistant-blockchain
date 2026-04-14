from __future__ import annotations

from qr_blockchain.api import serve
from qr_blockchain.config import NodeConfig


def main() -> None:
    serve(NodeConfig.from_env())


if __name__ == "__main__":
    main()
