class StandardRaffle:
    def __init__(self):
        self.name = "Standard"
        self.description = "The standard raffle will pick a winner at random."
        self.features = {
            "random_winner": True,
            "entry_limit": True,
            "test_mode": True,
            # Add more features as needed
        }

    def pick_winner(self, participants):
        """Logic to pick a random winner from the participants."""
        # Implement your random winner selection logic here
        pass
