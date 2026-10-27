"""Defanged fake secrets with the shape of real ones (never real credentials)."""

GITHUB = "ghp_" + "EXAMPLE" * 5 + "0"
GITHUB_PAT = "github_pat_" + "EXAMPLE0123456789abcdef"
ANTHROPIC = "sk-ant-api03-" + "EXAMPLEexampleEXAMPLE0123"
OPENAI = "sk-proj-" + "EXAMPLEexampleEXAMPLE0123456789"
AWS = "AKIA" + "EXAMPLEEXAMPLE00"
SLACK = "xoxb-" + "1234567890-EXAMPLEexample"
GOOGLE = "AIza" + "EXAMPLEexampleEXAMPLE0123456789abcd"
GITLAB = "glpat-" + "EXAMPLEexample0123456789"
HUGGING_FACE = "hf_" + "EXAMPLEexampleEXAMPLE0123456789ab"
NPM = "npm_" + "EXAMPLEexampleEXAMPLE0123456789abcde"
SLACK_WEBHOOK_SECRET = "EXAMPLEexample0123456789"
SLACK_WEBHOOK = f"https://hooks.slack.com/services/T0EXAMPLE/B0EXAMPLE/{SLACK_WEBHOOK_SECRET}"
DISCORD_WEBHOOK_SECRET = "EXAMPLEexample_0123456789-abc"
DISCORD_WEBHOOK = f"https://discord.com/api/webhooks/123456789012345678/{DISCORD_WEBHOOK_SECRET}"
BEARER_SECRET = "EXAMPLEexampleEXAMPLE0123456789.abc"
BEARER = f"Bearer {BEARER_SECRET}"
GENERIC = "Zx9fQ2mK7pL4vR8tY1nB6cD3wH5jS0aE"

# (label, full value, the secret part that must never be printed)
KNOWN = [
    ("GitHub token", GITHUB, GITHUB),
    ("GitHub fine-grained token", GITHUB_PAT, GITHUB_PAT),
    ("Anthropic API key", ANTHROPIC, ANTHROPIC),
    ("OpenAI API key", OPENAI, OPENAI),
    ("AWS access key", AWS, AWS),
    ("Slack token", SLACK, SLACK),
    ("Google API key", GOOGLE, GOOGLE),
    ("GitLab token", GITLAB, GITLAB),
    ("Hugging Face token", HUGGING_FACE, HUGGING_FACE),
    ("npm token", NPM, NPM),
    ("Slack webhook", SLACK_WEBHOOK, SLACK_WEBHOOK_SECRET),
    ("Discord webhook", DISCORD_WEBHOOK, DISCORD_WEBHOOK_SECRET),
    ("Bearer token", BEARER, BEARER_SECRET),
]
