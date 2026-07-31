"""
MetasploitMCP - A Model Context Protocol server for Metasploit Framework.

This package provides AI assistants with controlled access to Metasploit
functionality through the MCP protocol.
"""

from .server import mcp, logger

__version__ = "3.1.0"
__all__ = ["main", "mcp", "logger", "__version__"]


def main():
    """Main entry point for the metasploit-mcp CLI command."""
    from .server import (
        initialize_msf_client,
        configure_event_loop_debugging,
        stop_event_loop_monitoring,
        cleanup_msf_client,
        handle_asyncio_exception,
        find_available_port,
        mcp,
        logger,
    )
    import sys
    import asyncio
    import argparse

    # Initialize MSF Client - Critical for server function
    try:
        initialize_msf_client()
    except (ValueError, ConnectionError, RuntimeError) as e:
        logger.critical(
            f"CRITICAL: Failed to initialize Metasploit client on startup: {e}. "
            "Server cannot function."
        )
        sys.exit(1)

    # Configure event loop debugging if enabled via environment variables
    configure_event_loop_debugging()

    # Set custom exception handler for asyncio event loop
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            logger.debug(
                "Event loop is already running, exception handler will be set on next loop creation"
            )
        else:
            loop.set_exception_handler(handle_asyncio_exception)
            logger.debug("Custom asyncio exception handler installed")
    except RuntimeError:
        logger.debug("No event loop exists yet, will set exception handler after loop creation")

    # Setup argument parser
    parser = argparse.ArgumentParser(description="Run MetasploitMCP Server")
    parser.add_argument(
        "--transport",
        choices=["http", "stdio"],
        default="http",
        help="MCP transport mode to use (http=HTTP POST, stdio=direct pipe)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the HTTP server to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to listen on (default: find available from 8085)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload (for development)",
    )
    parser.add_argument(
        "--find-port",
        action="store_true",
        help="Force finding an available port starting from --port or 8085",
    )
    parser.add_argument(
        "--allow-dangerous",
        action="store_true",
        default=None,
        help=(
            "Enable state-changing / offensive tools (exploit & module execution, "
            "payload generation, session control, listeners). Disabled by default. "
            "Can also be set with MSF_MCP_ALLOW_DANGEROUS=true."
        ),
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Max dangerous-tool requests per minute (0 disables the limit). "
            "Default 60; can also be set with MSF_MCP_RATE_LIMIT."
        ),
    )
    parser.add_argument(
        "--confirm-dangerous",
        action="store_true",
        default=None,
        help=(
            "Ask the client to confirm (via MCP elicitation) before each destructive "
            "action. Falls back to the gate if the client can't elicit. Can also be "
            "set with MSF_MCP_CONFIRM_DANGEROUS=true."
        ),
    )
    args = parser.parse_args()

    # Apply the safety posture (CLI overrides environment). Dangerous actions stay
    # disabled unless explicitly enabled here or via MSF_MCP_ALLOW_DANGEROUS.
    from .server import configure_safety

    configure_safety(
        allow_dangerous=True if args.allow_dangerous else None,
        rate_limit_per_min=args.rate_limit,
        require_confirmation=True if args.confirm_dangerous else None,
    )
    if args.allow_dangerous:
        logger.warning(
            "Dangerous actions ENABLED: exploit/module execution, payload generation, "
            "and session/listener control are permitted."
        )
    else:
        logger.info(
            "Dangerous actions disabled (default). Read-only tools only; pass "
            "--allow-dangerous to enable offensive tools."
        )

    if args.transport == "stdio":
        logger.info("Starting MCP server in STDIO transport mode.")
        try:
            mcp.run(transport="stdio")
        except Exception as e:
            logger.exception("Error during MCP stdio run loop.")
            sys.exit(1)
        finally:
            logger.info("Shutting down - cleaning up MSF resources...")
            cleanup_msf_client()
            stop_event_loop_monitoring()
            logger.info("Shutdown complete.")
        logger.info("MCP stdio server finished.")
    else:  # HTTP mode (default)
        logger.info("Starting MCP server in HTTP transport mode.")

        check_host = args.host if args.host != "0.0.0.0" else "127.0.0.1"
        selected_port = args.port
        if selected_port is None or args.find_port:
            start_port = selected_port if selected_port is not None else 8085
            selected_port = find_available_port(start_port, host=check_host)

        mcp.settings.host = args.host
        mcp.settings.port = selected_port

        logger.info(f"Starting FastMCP HTTP server on http://{args.host}:{selected_port}")
        logger.info(f"MCP Endpoint:    http://{args.host}:{selected_port}/mcp")
        logger.info(f"Health Check:    http://{args.host}:{selected_port}/health")

        try:
            loop = asyncio.get_event_loop()
            if not loop.is_running():
                loop.set_exception_handler(handle_asyncio_exception)
        except RuntimeError:
            pass

        try:
            mcp.run(transport="streamable-http")
        except Exception as e:
            logger.exception("Error during MCP HTTP server run.")
            sys.exit(1)
        finally:
            logger.info("Shutting down - cleaning up MSF resources...")
            cleanup_msf_client()
            stop_event_loop_monitoring()
            logger.info("Shutdown complete.")


if __name__ == "__main__":
    main()
