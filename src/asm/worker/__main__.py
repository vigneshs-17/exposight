"""CLI entry point for running the ASM background worker."""

import logging
import sys

from asm.config import enforce_production_config
from asm.db.session import get_engine
from asm.worker.worker import ASMWorker

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)


def main() -> int:
    enforce_production_config(check_auth=False)
    worker = ASMWorker(engine=get_engine())
    try:
        worker.run()
        return 0
    except (KeyboardInterrupt, SystemExit):
        return 0
    except Exception as exc:
        logging.getLogger("asm.worker").exception("Fatal worker crash: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
