# Integration test package for ForensiX AI (Phase 16).
#
# These tests exercise interactions BETWEEN modules end-to-end
# (collector -> normalizer -> pipeline -> database -> hash chain ->
# correlation -> behavior -> investigation -> report -> API), rather than
# re-testing any single module in isolation. Every test runs against a
# throwaway temporary database and never touches the real forensic store.
