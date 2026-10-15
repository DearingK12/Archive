
# Python To-Do List Manager
# Name: Koda R Dearing

import json
import os

FILE_NAME = "tasks.json"

tasks = []


# Load saved tasks from the file
def load_tasks():
    global tasks

    if os.path.exists(FILE_NAME):
        try:
            with open(FILE_NAME, "r") as file:
                tasks = json.load(file)
        except (json.JSONDecodeError, OSError):
            print("Could not load saved tasks.")
            tasks = []


# Save tasks to the file
def save_tasks():
    try:
        with open(FILE_NAME, "w") as file:
            json.dump(tasks, file, indent=4)
    except OSError:
        print("Error: Could not save tasks.")


# Add a new task
def add_task():
    task_name = input("Enter your new task: ").strip()

    if task_name == "":
        print("Task cannot be empty.")
        return

    task = {
        "name": task_name,
        "completed": False
    }

    tasks.append(task)
    save_tasks()

    print(f'Task "{task_name}" added successfully!')


# Display all tasks
def view_tasks():
    print("\n========== YOUR TASKS ==========")

    if not tasks:
        print("You have no tasks yet.")
        return

    for index, task in enumerate(tasks, start=1):
        if task["completed"]:
            status = "x"
        else:
            status = " "

        print(f'{index}. [{status}] {task["name"]}')

    print("================================")


# Mark a task as complete
def complete_task():
    view_tasks()

    if not tasks:
        return

    try:
        task_number = int(input("Enter the task number to complete: "))

        if task_number < 1 or task_number > len(tasks):
            print("Invalid task number.")
            return

        task = tasks[task_number - 1]

        if task["completed"]:
            print("This task is already complete.")
        else:
            task["completed"] = True
            save_tasks()
            print(f'Task "{task["name"]}" completed!')

    except ValueError:
        print("Please enter a valid number.")


# Delete a task
def delete_task():
    view_tasks()

    if not tasks:
        return

    try:
        task_number = int(input("Enter the task number to delete: "))

        if task_number < 1 or task_number > len(tasks):
            print("Invalid task number.")
            return

        removed_task = tasks.pop(task_number - 1)
        save_tasks()

        print(f'Task "{removed_task["name"]}" deleted!')

    except ValueError:
        print("Please enter a valid number.")

    def Welcome():
        print("Welcome to my Python Task Manager, This took me forever! please choose an option!!")
# Main program
def main():
    load_tasks()

    print("==================================")
    print("       PYTHON TASK MANAGER")
    print("==================================")

    Welcome()

    while True:
        print("\nSelect an option:")
        print("1. Add a task")
        print("2. View tasks")
        print("3. Complete a task")
        print("4. Delete a task")
        print("5. Exit")

        choice = input("\nEnter your choice: ")

        if choice == "1":
            add_task()

        elif choice == "2":
            view_tasks()

        elif choice == "3":
            complete_task()

        elif choice == "4":
            delete_task()

        elif choice == "5":
            print("Thanks for using the Task Manager!")
            break

        else:
            print("Invalid choice. Please try again.")


# Run the program
if __name__ == "__main__":
    main()
