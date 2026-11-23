import builtins
import types
import pytest
from unittest import mock

# Import the module under test
import Backend.services.domain_collector as dc

# Helper to create a fake response object
class FakeResponse:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status

# Test get_phishing_urls normal behavior
def test_get_phishing_urls_success(monkeypatch):
    sample_text = "http://phish1.com\nhttps://phish2.com\n\nhttp://phish3.com"
    monkeypatch.setattr(dc.requests, "get", lambda url, timeout: FakeResponse(sample_text))
    urls = dc.get_phishing_urls(limit=2)
    assert urls == ["http://phish1.com", "https://phish2.com"]
    # Ensure limit respected
    urls_all = dc.get_phishing_urls(limit=10)
    assert urls_all == ["http://phish1.com", "https://phish2.com", "http://phish3.com"]

# Test get_phishing_urls with non-200 status
def test_get_phishing_urls_non200(monkeypatch, capsys):
    monkeypatch.setattr(dc.requests, "get", lambda url, timeout: FakeResponse("error", status=404))
    urls = dc.get_phishing_urls()
    captured = capsys.readouterr()
    assert "Failed to fetch data" in captured.out
    assert urls == []

# Test get_phishing_urls exception handling
def test_get_phishing_urls_exception(monkeypatch, capsys):
    def raise_exc(url, timeout):
        raise RuntimeError("network")
    monkeypatch.setattr(dc.requests, "get", raise_exc)
    urls = dc.get_phishing_urls()
    captured = capsys.readouterr()
    assert "Error fetching data:" in captured.out
    assert urls == []

# Mock the LLM to test analyze_urls
class DummyLLM:
    def __init__(self):
        self.invoked = False
        self.last_prompt = None

    def invoke(self, prompt):
        self.invoked = True
        self.last_prompt = prompt
        # Return an object with content attribute
        return types.SimpleNamespace(content="analysis result")

def test_analyze_urls_calls_llm(monkeypatch):
    dummy_llm = DummyLLM()
    monkeypatch.setattr(dc, "llm", dummy_llm)
    urls = ["http://bad.com", "https://evil.com"]
    result = dc.analyze_urls(urls)
    assert dummy_llm.invoked
    assert "http://bad.com" in dummy_llm.last_prompt
    assert "https://evil.com" in dummy_llm.last_prompt
    assert result == "analysis result"

# Ensure analyze_urls handles empty list gracefully
def test_analyze_urls_empty(monkeypatch):
    dummy_llm = DummyLLM()
    monkeypatch.setattr(dc, "llm", dummy_llm)
    result = dc.analyze_urls([])
    assert dummy_llm.invoked
    assert "URLs:" in dummy_llm.last_prompt
    assert result == "analysis result"

# Verify that the LLM model is correctly set to a Groq model
def test_llm_model_name():
    assert dc.llm.model == "llama3-8b-8192"

# Ensure that the module does not crash when imported
def test_module_import():
    import importlib
    mod = importlib.import_module("Backend.services.domain_collector")
    assert hasattr(mod, "get_phishing_urls")
    assert hasattr(mod, "analyze_urls")