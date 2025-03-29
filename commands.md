# Discord Bot Commands

This document outlines the available commands for the Discord bot.

## General Commands

*   None explicitly defined in the provided code. The bot may respond to basic messages (e.g., "!hello" in the webapp), but these are not formal commands.

## Admin Commands

*These commands require the user to have the designated admin role.*

*   `!start [name] [raffle_type]`
    *   **Description:** Start the raffle.
    *   **Usage:** `!start [name] [raffle_type]`
    *   **Parameters:**
        *   `name` (optional): The name of the raffle. If not provided, a default name will be used.
        *   `raffle_type` (optional): The type of raffle (e.g., 'standard', 'lucky_number'). Defaults to 'standard'.
    *   **Example:**
        ```
        !start My Awesome Raffle standard
        ```

*   `!end`
    *   **Description:** End the raffle and pick a winner.
    *   **Usage:** `!end`
    *   **Example:**
        ```
        !end
        ```

*   `!setlimit <limit>`
    *   **Description:** Set the participant limit for the raffle.
    *   **Usage:** `!setlimit <limit>`
    *   **Parameters:**
        *   `<limit>`: The maximum number of participants allowed in the raffle.
    *   **Example:**
        ```
        !setlimit 100
        ```

*   `!add <user> <entry_number> [entries]`
    *   **Description:** Add a user to the raffle.
    *   **Usage:** `!add <user> <entry_number> [entries]`
    *   **Parameters:**
        *   `<user>`: The Discord member to add to the raffle (mention them).
        *   `<entry_number>`: The entry number for the user.
        *   `<entries>` (optional): The number of entries to give the user. Defaults to 1.
    *   **Example:**
        ```
        !add @User#1234 1 2
        ```

*   `!remove <user>`
    *   **Description:** Remove a user from the raffle.
    *   **Usage:** `!remove <user>`
    *   **Parameters:**
        *   `<user>`: The Discord member to remove from the raffle (mention them).
    *   **Example:**
        ```
        !remove @User#1234
        ```

*   `!list`
    *   **Description:** List all participants in the raffle.
    *   **Usage:** `!list`
    *   **Example:**
        ```
        !list
        ```

*   `!clear`
    *   **Description:** Clear the raffle, removing all participants.
    *   **Usage:** `!clear`
    *   **Example:**
        ```
        !clear
        ```

*   `!archive`
    *   **Description:** Archive the raffle.
    *   **Usage:** `!archive`
    *   **Example:**
        ```
        !archive
        ```

*   `!setname <name>`
    *   **Description:** Sets the name of the raffle.
    *   **Usage:** `!setname <name>`
    *   **Parameters:**
        *   `<name>`: The new name for the raffle.
    *   **Example:**
        ```
        !setname Grand Prize Raffle
        ```

*   `!setwebhook <url>`
    *   **Description:** Sets the webhook URL for the raffle.
    *   **Usage:** `!setwebhook <url>`
    *   **Parameters:**
        *   `<url>`: The webhook URL.
    *   **Example:**
        ```
        !setwebhook https://discord.com/api/webhooks/...
        ```

*   `!setentrylimit <limit>`
    *   **Description:** Sets the entry limit for each participant.
    *   **Usage:** `!setentrylimit <limit>`
    *   **Parameters:**
        *   `<limit>`: The maximum number of entries each participant can have.
    *   **Example:**
        ```
        !setentrylimit 5
        ```

*   `!settype <raffle_type>`
    *   **Description:** Sets the raffle type.
    *   **Usage:** `!settype <raffle_type>`
    *   **Parameters:**
        *   `<raffle_type>`: The type of raffle (e.g., 'standard', 'lucky_number').
    *   **Example:**
        ```
        !settype lucky_number
        ```

*   `!setadminrole <role>`
    *   **Description:** Sets the admin role for the raffle.
    *   **Usage:** `!setadminrole <role>`
    *   **Parameters:**
        *   `<role>`: The Discord role that has admin privileges (mention the role).
    *   **Example:**
        ```
        !setadminrole @RaffleAdmin
        ```

*   `!setchannel <channel>`
    *   **Description:** Sets the channel for the raffle.
    *   **Usage:** `!setchannel <channel>`
    *   **Parameters:**
        *   `<channel>`: The Discord text channel to use for the raffle (mention the channel).
    *   **Example:**
        ```
        !setchannel #raffle-channel
        ```

*   `!setluckynumber <number>`
    *   **Description:** Sets the lucky number for lucky number raffles.
    *   **Usage:** `!setluckynumber <number>`
    *   **Parameters:**
        *   `<number>`: The lucky number.
    *   **Example:**
        ```
        !setluckynumber 7
        ```

## Slash Commands and Context Menu Commands

*These commands are registered as slash commands and context menu commands and are accessed through the Discord command interface.*

*   `/sync`
    *   **Description:** Syncs the bot's slash commands with the Discord server. This is typically used after the bot's commands have been updated.
    *   **Usage:** `/sync`
    *   **Permissions:** Requires administrator privileges.

*   `Start Raffle` (Context Menu - Message)
    *   **Description:** Starts a raffle from a selected message.
    *   **Usage:** Right-click on a message, select "Apps", then "Start Raffle".
    *   **Permissions:** Requires administrator privileges.

*   `End Raffle` (Context Menu - Message)
    *   **Description:** Ends a raffle from a selected message.
    *   **Usage:** Right-click on a message, select "Apps", then "End Raffle".
    *   **Permissions:** Requires administrator privileges.

## Notes

*   Replace `<user>`, `<role>`, and `<channel>` with the actual mentions from your Discord server.
*   Admin commands are only accessible to users who have the specified admin role.
*   The bot must have the necessary permissions in the Discord server to execute commands.