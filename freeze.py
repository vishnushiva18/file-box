from flask_frozen import Freezer
from fileStorage import app


freezer = Freezer(app)

if __name__ == '__main__':
    freezer.freeze()
    