from celery import shared_task
from django_db_logger.models import StatusLog
from operator import itemgetter
from bs4 import BeautifulSoup
import requests
from server_app_dev.celery import app
import shutil


@app.task()
def make_report():
    f = open('requests_report.txt', 'w')
    requests = list(StatusLog.objects.values_list('msg', flat=True))
    for i in range(len(requests)):
        requests[i] = ' '.join(requests[i].split(' ')[:-1])
    unique_requests = list(set(requests))
    requests_rating = []
    for unique_request in unique_requests:
        requests_rating.append({'count': requests.count(unique_request), 'request': unique_request})
    sorted_rating = sorted(requests_rating, key=itemgetter('count'), reverse=True)
    for request in sorted_rating:
        f.write(str(request['count']) + ' - ' + request['request'] + '\n')
    f.close()
    shutil.move('./requests_report.txt', './reports/requests_report.txt')

@app.task()
def parse_events():
    request = requests.get("https://hanty-mansiysk.info/afisha")
    soup = BeautifulSoup(request.content, features="html.parser")
    articles_block = soup.find_all("div", {"class": "col-md-9"})
    f = open('events_report.txt', 'w')
    for item in articles_block:
        el = (
        {"tittle": item.h2.a.text.replace(u'\xa0', u' '), 
            "date": item.p.strong.text.replace(u'\xa0', u' '), 
            "category": item.p.span.i.text.replace(u'\xa0', u' '), 
            "place": item.p.span.strong.text.replace(u'\xa0', u' ')}        
        )
        f.write(str(el) + '\n')
    f.close()
    shutil.move('./events_report.txt', './reports/events_report.txt')