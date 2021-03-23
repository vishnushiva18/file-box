import os
from telethon import TelegramClient, events, sync, types
from flask import (Flask,session, g, json, Blueprint,flash, jsonify, redirect, render_template, request,
                   url_for, send_from_directory)
from werkzeug.utils import secure_filename
from asgiref.sync import async_to_sync, sync_to_async
import asyncio

app = Flask(__name__)
app.config.from_object(__name__)

client = None
api_id = 50689
api_hash = '2b7f12faf2e1f06d9403213185525af2'
    
async def getMe(loop):
    async with TelegramClient('file_storage', api_id, api_hash, loop = loop) as client:
        r = await client.get_me()

        print(r)
        return r

@app.route('/')
def home():
    loop = asyncio.new_event_loop()
    print('new loop: ', loop)
    r = loop.run_until_complete(getMe(loop))
    print(r)

    return "vishnu"


if __name__ == '__main__':
    app.run('0.0.0.0' , 5001 , threaded=True)