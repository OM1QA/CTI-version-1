"""Date parsing and formatting utilities"""

from datetime import datetime, timezone
import feedparser

def format_date(date_obj):
    """Format date object to readable string"""
    if isinstance(date_obj, str):
        return date_obj
    return date_obj.strftime('%Y-%m-%d') if date_obj else 'Unknown'

def parse_rss_date(date_string):
    """Parse various RSS date formats with timezone awareness"""
    try:
        parsed_date = feedparser._parse_date(date_string)
        if parsed_date:
            dt = datetime(*parsed_date[:6])
            # Make timezone-aware
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
    except:
        pass
    
    # Fallback to current time with UTC timezone
    return datetime.now(timezone.utc)
