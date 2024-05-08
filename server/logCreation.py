import random
from datetime import datetime, timedelta

# Define users
users = ["ek6l_hrk0_1ntm_gp4m", "vkfh_dskb_s4r3_p760"]

# Define types of log messages
log_types = [
    "+ User {} has requested: {} beds, {} tables, {} chairs, and {} armchairs.",
    "- User {}, has done too many requests.",
    "- User {}, has requested too many materials.",
    "- A message from a non-verified user has been received.",
    "- User {} message has been corrupted."
]

# Create a function to simulate log entries
def generate_log_entry(start_date: datetime, end_date: datetime):
    user = random.choice(users)
    # Generate a random date between the given start and end dates
    delta_days = (end_date - start_date).days
    random_days = random.randint(0, delta_days)
    date = start_date + timedelta(days=random_days)
    
    log_type = random.choice(log_types)
    if "too many" in log_type:
        message = log_type.format(user)
    elif "corrupted" in log_type:
        message = log_type.format(user)
    elif "non-verified" in log_type:
        message = log_type
    else:
        beds = random.randint(1, 300)
        tables = random.randint(1, 300)
        chairs = random.randint(1, 300)
        armchairs = random.randint(1, 300)
        message = log_type.format(user, beds, tables, chairs, armchairs)
    return f"{message} On day: {date.strftime('%d/%m/%Y')}"

# Set the date range for the whole month of May
may_start = datetime(datetime.now().year, 5, 1)
may_end = datetime(datetime.now().year, 5, 31)

# Generate 70 log entries for the month of May
log_entries = [generate_log_entry(may_start, may_end) for _ in range(70)]

# Write log entries to file
log_filename = f"logs/{datetime.now().strftime('%m-%Y')}.log"
with open(log_filename, 'w') as f:
    for entry in log_entries:
        f.write(entry + "\n")

print(f"Generated log entries for the month of May in '{log_filename}'")
