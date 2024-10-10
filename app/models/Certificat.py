class Certificat:
    def __init__(self, issuer, issued_date, exipration_date, days_left_before_expiration):
        self.issuer:str = issuer
        self.issued_date:str = issued_date
        self.expiration_date:str = exipration_date
        self.days_left_before_expiration:str = days_left_before_expiration
