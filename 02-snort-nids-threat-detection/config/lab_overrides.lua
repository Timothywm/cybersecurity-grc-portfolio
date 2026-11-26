alert_fast = { file = true, packet = false }

event_filter =
{
    { gid = 1, sid = 1000001, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 1000002, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 1000004, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
}
