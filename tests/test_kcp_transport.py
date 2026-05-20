import pytest

from kcp_transport import CMD_ACK, KcpFrame, KcpSession


def test_frame_round_trip():
    frame = KcpFrame(conv=7, cmd=81, seq=3, ack=2, payload=b"hello")

    decoded = KcpFrame.decode(frame.encode())

    assert decoded == frame


def test_frame_rejects_truncated_payload():
    raw = KcpFrame(conv=7, cmd=81, seq=3, ack=2, payload=b"hello").encode()

    with pytest.raises(ValueError):
        KcpFrame.decode(raw[:-1])


def test_session_acks_and_delivers_ordered_payload():
    sender = KcpSession(11, now=0)
    receiver = KcpSession(11, now=0)

    frames = sender.queue_data(b"abc", now=0)
    replies = receiver.input_frame(frames[0], now=0.01)
    sender.input_frame(replies[0], now=0.02)

    assert receiver.recv_ready() == [b"abc"]
    assert sender.inflight_count == 0
    assert replies[0].cmd == CMD_ACK
    assert replies[0].ack == 1


def test_session_retransmits_after_timeout():
    session = KcpSession(12, resend_after=0.1, now=0)
    frames = session.queue_data(b"abc", now=0)

    assert session.tick(now=0.05) == []
    resend = session.tick(now=0.11)

    assert resend == frames
    assert session.inflight_count == 1


def test_session_closes_after_retry_budget():
    session = KcpSession(12, resend_after=0.1, max_retries=1, now=0)
    session.queue_data(b"abc", now=0)
    session.tick(now=0.11)

    with pytest.raises(TimeoutError):
        session.tick(now=0.22)
    assert session.closed


def test_session_rejects_wrong_conversation():
    session = KcpSession(12, now=0)

    with pytest.raises(ValueError):
        session.input_frame(KcpFrame(13, 81, 1, 0, b"x"), now=0)
