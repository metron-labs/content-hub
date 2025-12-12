from __future__ import annotations

from SiemplifyUtils import output_handler
from DoppelManager import DoppelManager

@output_handler
def main():
    siemplify, manager = DoppelManager.from_siemplify()
    siemplify.script_name = "DoppelVision - Ping"

    success = manager.connection_test()
    siemplify.end(
        "Connection successful!" if success else "Connection failed. Check credentials.",
        success
    )

if __name__ == "__main__":
    main()