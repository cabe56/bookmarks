from datetime import date, timedelta
import math
from itertools import chain

# To run doctests call: python -m doctest -v main.py

def tags(l, tag_attr='tags'):
    """Return list of unique tags found in list of dicts
    >>> t = tags([{'tags': ['a', 'b']}, {'tags':['b','c']}])
    >>> sorted(list(t))
    ['a', 'b', 'c']
    """
    return set(chain.from_iterable(map(lambda x: x.get(tag_attr, []), l)))

def filter_list(l, attr, val):
    """Shorthand from std lib filter.
    >>> l = [{'a': 1}, {'a':10}]
    >>> filter_list(l, 'a', 1)
    [{'a': 1}]
    """
    return filter(lambda el: el[attr] == val, l)

def urls(object_list, url_attr='url'):
    """Return list of url strings found in objet_list.
    >>> l = [{'url': 'google.com'}]
    >>> urls(l)[0]
    'google.com'
    >>> l = [{'resolved_url': 'google.com'}]
    >>> urls(l, 'resolved_url')[0]
    'google.com'
    """
    return map(lambda o: o[url_attr], object_list)

def total_urls_to_process_today(url_count, limit_date):
    """
    Return int representing number of items that should be removed from list
    today in order to reach url_count == 0 by limit_date.
    >>> today = date.today()
    >>> total_urls_to_process_today(2, today)
    2
    >>> total_urls_to_process_today(1, today + timedelta(days=1))
    1
    >>> total_urls_to_process_today(45, today + timedelta(days=10))
    5
    """
    today = date.today()
    assert today <= limit_date
    days_left = float((limit_date - date.today()).days)
    if days_left == 0:
        return url_count
    else:
        return int(math.ceil(url_count/days_left))
