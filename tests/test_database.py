from backend.database.db import get_connection, get_events, get_event_by_id


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

    # Assert that event was inserted
    assert event is not None, "Event should have been inserted"
    assert event['source'] == 'USB', "Event source should be USB"
    assert event['event_type'] == 'USB_CONNECTED', "Event type should be USB_CONNECTED"


def test_get_events():
    """Test retrieving all events."""
    events = get_events()
    
    # Assert events were retrieved
    assert isinstance(events, list), "get_events() should return a list"
    assert len(events) > 0, "Should have at least one event in the database"
    
    # Assert event structure
    for event in events:
        assert event['timestamp'] is not None, "Event should have timestamp"
        assert event['source'] is not None, "Event should have source"
        assert event['event_type'] is not None, "Event should have event_type"
        assert event['description'] is not None, "Event should have description"


def test_get_events_chronological():
    """Test that events are returned in chronological order."""
    events = get_events()
    
    # Need at least 2 events to test ordering
    assert len(events) >= 2, "Need at least 2 events to test chronological ordering"
    
    # Verify chronological ordering
    for i in range(len(events) - 1):
        current_timestamp = events[i]['timestamp']
        next_timestamp = events[i + 1]['timestamp']
        assert current_timestamp <= next_timestamp, \
            f"Events not in chronological order: {current_timestamp} > {next_timestamp}"


def test_get_events_limit():
    """Test limit parameter."""
    all_events = get_events()
    limited_events = get_events(limit=1)
    
    assert len(all_events) > 0, "Should have events in database"
    assert len(limited_events) == 1, \
        f"get_events(limit=1) should return exactly 1 event, got {len(limited_events)}"
    assert limited_events[0]['id'] == all_events[0]['id'], \
        "Limited event should be the first event chronologically"


def test_get_event_by_id():
    """Test retrieving an event by ID."""
    # Insert a test event first
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
        "2026-09-20 19:00:00",
        "FILE",
        "FILE_CREATE",
        "Test file created",
        "INFO",
        "TestUser",
        "TestDevice",
        "C:\\test.txt",
        "{}"
    ))
    connection.commit()

    # Get the inserted event's ID
    cursor = connection.execute("SELECT last_insert_rowid()")
    event_id = cursor.fetchone()[0]
    connection.close()

    # Retrieve it using get_event_by_id
    event = get_event_by_id(event_id)

    # Assertions
    assert event is not None, "Event should exist"
    assert event['id'] == event_id, f"Event ID should match: {event['id']} == {event_id}"
    assert event['source'] == 'FILE', f"Event source should be FILE, got {event['source']}"
    assert event['event_type'] == 'FILE_CREATE', f"Event type should be FILE_CREATE, got {event['event_type']}"


def test_get_event_by_id_not_found():
    """Test that get_event_by_id returns None for non-existent ID."""
    # Use a very large ID that won't exist
    non_existent_id = 999999
    event = get_event_by_id(non_existent_id)

    assert event is None, f"Event should not exist for non-existent ID, got {event}"


if __name__ == "__main__":
    test_insert_event()
    test_get_events()
    test_get_events_chronological()
    test_get_events_limit()
    test_get_event_by_id()
    test_get_event_by_id_not_found()