def scope_creep(event):
    token = event.get("token")
    object_type, action = event.get("request_query")
    new_event = f"{object_type}:{action}"
    normal_scope = token.get("scope")

    if new_event not in normal_scope:
        return True
    return False


    

    