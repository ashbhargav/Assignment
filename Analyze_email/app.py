try:
    from flask import Flask, request, render_template, redirect, url_for, flash
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing dependency 'flask'. Run 'pip install -r requirements.txt' and try again."
    ) from exc

from detector import analyze, SUMMARY

app = Flask(__name__)
app.secret_key = 'dev-secret-change-in-prod'


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_email():
    if 'email_file' not in request.files or request.files['email_file'].filename == '':
        flash('No file selected.')
        return redirect(url_for('index'))

    f = request.files['email_file']

    try:
        content = f.read().decode('utf-8')
    except UnicodeDecodeError:
        flash('Could not read file — make sure it is a plain UTF-8 text file.')
        return redirect(url_for('index'))

    result = analyze(content)
    result['summary'] = SUMMARY[result['verdict']]
    return render_template('result.html', result=result)


if __name__ == '__main__':
    app.run(port=5001)
