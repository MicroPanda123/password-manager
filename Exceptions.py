class Error(Exception):
    """
    Base expection
    """
    pass

class UserAlreadyWithPassword(Error):
    """
    Raised when user already has password assigned to them in config file
    """
    pass

class UserAlreadyExists(Error):
    """
    Raised when trying to create new user while it already exists
    """
    pass

class UserNotFound(Error):
    """
    Raised when user was not found in config file
    """
    pass

class WrongPassword(Error):
    """
    Raised when password is incorrect
    """
    pass

class NoPasswordGiven(Error):
    """
    Raised when no password was given
    """
    pass
