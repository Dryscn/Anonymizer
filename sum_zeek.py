import pandas as pd

def parse_weird_log(file_path):
    """Reads Zeek's weird.log and summarizes alerts."""

    # Read the log file while handling Zeek's format
    with open(file_path, "r") as file:
        lines = file.readlines()

    # Find the header line (skipping Zeek's metadata lines that start with #)
    header_line = None
    for i, line in enumerate(lines):
        if line.startswith("#fields"):
            header_line = i
            break
    
    if header_line is None:
        raise ValueError("Could not find header line in weird.log")

    # Extract column names from the header line
    columns = lines[header_line].strip().split("\t")[1:]

    # Read data, skipping comment lines
    data = pd.read_csv(file_path, delimiter="\t", comment="#", names=columns, skiprows=header_line + 1, low_memory=False)

    # Convert timestamp to readable format
    data["ts"] = pd.to_datetime(data["ts"], unit="s")

    # Select relevant columns
    relevant_columns = ["ts", "id.orig_h", "id.resp_h", "name", "addl"]
    data = data[relevant_columns]

    # Count occurrences of each "weird" event
    summary = data["name"].value_counts().reset_index()
    summary.columns = ["Weird Event", "Count"]

    # Display the summary
    print("\n🔹 **Summary of Weird Events:**")
    print(summary)

    # Show the top 5 alerts
    print("\n🔹 **Top 5 Alerts:**")
    print(data.head(5))

    return summary, data

# Run the function
if __name__ == "__main__":
    weird_log_file = "weird_SOC.log"  # Change this if your file is in a different location
    summary_df, weird_data = parse_weird_log(weird_log_file)

    if summary_df is not None:
        summary_df.to_csv("weird_summary.csv", index=False)
        print("\nSummary saved to 'weird_summary.csv'")
