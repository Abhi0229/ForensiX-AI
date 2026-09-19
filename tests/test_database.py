from backend.database.db import get_connection


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


if __name__ == "__main__":
    test_insert_event()