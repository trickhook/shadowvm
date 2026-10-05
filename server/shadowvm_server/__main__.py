def main():
    """Dispatch to either admin CLI or uvicorn server."""
    import sys
    if len(sys.argv) >= 2 and sys.argv[1] == "admin":
        from .cli import run
        run(sys.argv[2:])
        return
    from .server import run
    run()


if __name__ == "__main__":
    main()
