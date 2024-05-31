def user_mapping_fn(**fields):
    return {
        "first_name": fields["givenName"],
        "last_name": fields["surname"],
        "is_staff": True,
    }
