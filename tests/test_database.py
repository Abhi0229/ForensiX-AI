from backend.database.db import get_connection, get_events


def test_insert_event():
    connection = get_connection()

    connection.execute("""
        INSERT INTO events (
            timestamp,
            source,
            event_type,
            description,
            severity,
            user,
            device,
            file_path,
            metadata
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "2026-09-20 18:30:00",
        "USB",
        "USB_CONNECTED",
        "SanDisk USB device connected",
        "INFO",
        "Abhi",
        "SanDisk Ultra",
        "",
        "Vendor=SanDisk"
    ))

    connection.commit()

    cursor = connection.execute("""
        SELECT * FROM events
        ORDER BY id DESC
        LIMIT 1
    """)

    event = cursor.fetchone()

    connection.close()

    print("Inserted event:")
    print(dict(event))


def test_get_events():
    """Test retrieving all events."""
    events = get_events()
    print(f"\nRetrieved {len(events)} events")
    for event in events:
        print(f"  - {event['timestamp']} | {event['source']} | {event['event_type']}")


def test_get_events_chronological():
    """Test that events are returned in chronological order."""
    events = get_events()
    if len(events) < 2:
        print("\nNeed at least 2 events to test chronological order")
        return
    
    print("\nVerifying chronological order:")
    for i in range(len(events) - 1):
        current = events[i]['timestamp']
        next_event = events[i + 1]['timestamp']
        is_ordered = current <= next_event
        status = "✓" if is_ordered else "✗"
        print(f"  {status} {current} <= {next_event}")


def test_get_events_limit():
    """Test limit parameter."""
    all_events = get_events()
    limited_events = get_events(limit=1)
    
    print(f"\nTotal events: {len(all_events)}")
    print(f"Limited events (limit=1): {len(limited_events)}")
    
    if len(limited_events) <= 1:
        print("  ✓ Limit parameter works correctly")
    else:
        print("  ✗ Limit parameter not working")


if __name__ == "__main__":
    test_insert_event()
    test_get_events()
    test_get_events_chronological()
    test_get_events_limit()