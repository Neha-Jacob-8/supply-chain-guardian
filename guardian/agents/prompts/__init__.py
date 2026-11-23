"""Agent system prompts, shipped as package data (a hackathon deliverable)."""
from importlib import resources


def load(name):
    return resources.files(__package__).joinpath(f"{name}.md").read_text().strip()


def system(name):
    return load(name) + " " + load("guardrails")
