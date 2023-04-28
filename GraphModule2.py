import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

def count_chars(text):
    return Counter(text)

def plot_char_frequencies(plaintext, ciphertext):
    plaintext_counts = count_chars(plaintext)
    ciphertext_counts = count_chars(ciphertext)

    # Normalize counts to get frequencies
    plaintext_freqs = {char: count / len(plaintext) for char, count in plaintext_counts.items()}
    ciphertext_freqs = {char: count / len(ciphertext) for char, count in ciphertext_counts.items()}

    # Create a DataFrame with both frequency datasets
    import pandas as pd
    df_plaintext = pd.DataFrame(plaintext_freqs.items(), columns=["Character", "Frequency"])
    df_plaintext["Type"] = "Plaintext"
    df_ciphertext = pd.DataFrame(ciphertext_freqs.items(), columns=["Character", "Frequency"])
    df_ciphertext["Type"] = "Ciphertext"

    df = pd.concat([df_plaintext, df_ciphertext])

    # Create bar chart
    plt.figure(figsize=(12, 6))
    sns.barplot(x="Character", y="Frequency", hue="Type", data=df)
    plt.title("Character Frequency Analysis")
    plt.xlabel("Character")
    plt.ylabel("Frequency")
    plt.savefig('character_frequency_analysis.jpg', format='jpg', dpi=300)

# Example plaintext and ciphertext
plaintext = "this is a sample plaintext message for demonstrating character frequency analysis"
ciphertext = "irgw rg z rzmobv nrziztemh xlozomv ylw rftwzgfozazg oqzwoqol wvmnlorz"

plot_char_frequencies(plaintext, ciphertext)
