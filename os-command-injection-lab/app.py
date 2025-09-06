from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    output = ""
    if request.method == "POST":
        domain = request.form.get("domain", "")
        # ❌ VULNERABLE: unsanitized user input
        cmd = f"ping -c 2 {domain}"
        output = os.popen(cmd).read()
    return render_template_string("""
        <h2>🧪 OS Command Injection Lab</h2>
        <form method="post">
            Domain to ping: <input name="domain">
            <input type="submit">
        </form>
        <pre>{{output}}</pre>
    """, output=output)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
