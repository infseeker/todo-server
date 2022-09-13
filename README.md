# Welcome to Infseeker ToDo pet project!

This is server side of my first fullstack project. <br />
<br />
Client side: [todo-client](https://github.com/infseeker/todo-client) <br />
Live demo: [infseeker-todo.tk](https://infseeker-todo.tk/)


## Tech Stack
 - **API:** Flask
 - **Database:** PostgreSQL
 - **Web-server:** Gunicort + Nginx
 - **ORM:** Flask-SQLAlchemy + Flask Marshmallow
- **Authentication:** Flask Login
- **Authorization:** Flask Principal
- **SMTP-interface:** Flask Mail
- **Scheduler:** Flask APScheduler
- **Spam Protection:** Google reCaptcha v3
- **Admin:** Flask Admin
- **WebSocket:** Flask SocketIO


## Features
- No-DB list functionality for unauthorized users (Local Storage)
- User registration and auth (with Google Recaptcha 3) for extra features (include data storing in DB)
- Multiple list creation
- List sharing
- Real time shared list editing (WebSocket)
- Administration (with Flask Admin)
