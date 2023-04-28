
def playfair(final_plaintext,final_ciphertext):
    passage = final_plaintext
    finalplaintext = [passage[i:i+2] for i in range(0, len(passage), 2)]
    print(finalplaintext)
    passage = final_ciphertext 
    finalciphertext = [passage[i:i+2] for i in range(0, len(passage), 2)]
    print(finalciphertext)
    pairs_list = list(zip(finalplaintext,finalciphertext))
    global concatenated_strings
    concatenated_strings = concatenate_string_pairs(pairs_list)
# Print the list of pairs
#print(pairs_list)
def concatenate_string_pairs(pairs_list):
    concatenated_strings = []

    for s1, s2 in pairs_list:
        if s1[-1] == s2[0]:
            concatenated_strings.append(s1 + s2[1:])
        else:
            continue

    return concatenated_strings
def remove_duplicates(strings):
    # Convert the list to a set to remove duplicates, then convert back to a list
    unique_strings = list(set(strings))
    return unique_strings
unique_strings1 = remove_duplicates(concatenated_strings)

def append_strings(strings):
    output = []
    for i in range(len(strings)):
        chosen = strings[i]
        for j in range(len(strings)):
            if i != j and chosen[:2] == strings[j][-2:]:
                output.append(strings[j] + chosen[2:])
    return output

strings = unique_strings1
output1 = append_strings(strings)
output2 = append_strings(output1)
def remove_duplicate_characters(strings):
    unique_strings = []
    for string in strings:
        # Check if the string has the same characters as any of the unique strings
        is_duplicate = False
        for unique_string in unique_strings:
            if set(string) == set(unique_string):
                is_duplicate = True
                break
        if not is_duplicate:
            unique_strings.append(string)
    return unique_strings
unique_strings = remove_duplicate_characters(output2)
print(unique_strings)
def classify_strings(input_list):
    type_a_strings = set()
    non_type_a_strings = set()
    reference_string = input_list[0]
    non_type_a_strings.add(reference_string)

    for char in reference_string:
        for string in input_list[1:]:
            if char in string:
                type_a_strings.add(string)

    for string in input_list[1:]:
        if string not in type_a_strings:
            non_type_a_strings.add(string)

    return type_a_strings, non_type_a_strings
type_a_strings, non_type_a_strings = classify_strings(unique_strings)
print("Row strings", type_a_strings)
print("column strings", non_type_a_strings)
 
def remove_last_character(strings):
    new_strings = []
    for string in strings:
        # Remove the last character from the string
        new_string = string[:-1]
        new_strings.append(new_string)
    return new_strings

rowss = remove_last_character(type_a_strings)
colss = remove_last_character(non_type_a_strings)
matrix = [[string[i] for i in range(5)] for string in rowss]

# Print the matrix
for row in matrix:
    print(row)
first_string = colss[0]
my_list = list(first_string)
print(my_list)

for i in range(len(matrix)):
    if any(c in matrix[i] for c in my_list):
        while matrix[i][0] not in my_list:
            matrix[i] = matrix[i][1:] + [matrix[i][0]]
            
print(matrix)

sorted_matrix = []
for char in my_list:
    for row in matrix:
        if row[0] == char:
            sorted_matrix.append(row)
            break

print(sorted_matrix)

def print_matrix_row_major(matrix):
    # Initialize an empty string to hold the matrix elements
    matrix_string = ""

    # Iterate over the rows and columns of the matrix and concatenate the elements into a single string
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            matrix_string += str(matrix[i][j])

    # Print the matrix string
    return (matrix_string)

def print_matrix_column_major(matrix):
    # Initialize an empty string to hold the matrix elements
    matrix_string = ""

    # Iterate over the columns and rows of the matrix and concatenate the elements into a single string
    for j in range(len(matrix[0])):
        for i in range(len(matrix)):
            matrix_string += str(matrix[i][j])

    # Print the matrix string
    return (matrix_string)
answer=print_matrix_row_major(sorted_matrix)+"or"+print_matrix_column_major(sorted_matrix)
def getAnswer():
    return answer
