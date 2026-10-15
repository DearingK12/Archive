
# Simple Calculator
# Name: Koda R Dearing

def add(a, b):
    return a + b


def multi(a, b):
    return a * b


def sub(a, b):
    return a - b


def divide(a, b):
    if b == 0:
        return "ERROR: Cannot divide by 0 you silly goose!! Try another number!!"
    return a / b


def welcome():
    print("This took me forever! Please choose an option!!")


def Crazy():
    print("This is a crazy function I just wanted to add it for fun. Enjoy!")


def main():
    print("==================================")
    print(" Welcome to the Python Calculator!")
    print("==================================")

    welcome()

    while True:
        print("\nSelect an Operation!!")
        print("1. Addition")
        print("2. Multiply")
        print("3. Subtract")
        print("4. Divide")
        print("5. EXIT :(")

        choice = input("\nEnter your choice: ")

        if choice == "5":
            print("Thanks for using my Calculator! Please leave feedback on GitHub <3")
            break

        if choice not in ["1", "2", "3", "4"]:
            print("Invalid choice. Please try again.")
            continue

        try:
            num1 = float(input("Enter the first number: "))
            num2 = float(input("Enter the second number: "))
        except ValueError:
            print("Please enter valid numbers.")
            continue

        if choice == "1":
            result = add(num1, num2)
        elif choice == "2":
            result = multi(num1, num2)
        elif choice == "3":
            result = sub(num1, num2)
        elif choice == "4":
            result = divide(num1, num2)

        Crazy()
        print(f"\nResult: {result}")


if __name__ == "__main__":
    main()
