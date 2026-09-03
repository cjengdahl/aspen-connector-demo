"""A minimal blog app used to demo the aspen-connector."""

from flask import Flask, abort, redirect, render_template_string, request, url_for

app = Flask(__name__)

posts = [
    {"id": 1, "title": "Hello, World", "body": "This is the first post on this blog."},
    {"id": 2, "title": "Why We Blog", "body": "Blogging keeps us honest and helps us think."},
]

INDEX_TEMPLATE = """
<h1>Blog</h1>
<ul>
  {% for post in posts %}
    <li><a href="{{ url_for('view_post', post_id=post.id) }}">{{ post.title }}</a></li>
  {% endfor %}
</ul>
<a href="{{ url_for('new_post') }}">New post</a>
"""

POST_TEMPLATE = """
<h1>{{ post.title }}</h1>
<p>{{ post.body }}</p>
<a href="{{ url_for('index') }}">Back</a>
"""

NEW_POST_TEMPLATE = """
<h1>New post</h1>
<form method="post">
  <input name="title" placeholder="Title"><br>
  <textarea name="body" placeholder="Body"></textarea><br>
  <button type="submit">Publish</button>
</form>
"""


def next_id():
    return max((post["id"] for post in posts), default=0) + 1


@app.route("/")
def index():
    return render_template_string(INDEX_TEMPLATE, posts=posts)


@app.route("/post/<int:post_id>")
def view_post(post_id):
    post = next((p for p in posts if p["id"] == post_id), None)
    if post is None:
        abort(404)
    return render_template_string(POST_TEMPLATE, post=post)


@app.route("/post/new", methods=["GET", "POST"])
def new_post():
    if request.method == "POST":
        post = {
            "id": next_id(),
            "title": request.form.get("title", "Untitled"),
            "body": request.form.get("body", ""),
        }
        posts.append(post)
        return redirect(url_for("view_post", post_id=post["id"]))
    return render_template_string(NEW_POST_TEMPLATE)


if __name__ == "__main__":
    app.run(debug=False)
