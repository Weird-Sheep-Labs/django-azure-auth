def user_mapping_fn(**attributes):
    return {
        "first_name": attributes["givenName"],
        "last_name": attributes["surname"],
        "is_staff": True,
    }
