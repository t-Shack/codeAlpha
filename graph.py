import matplotlib.pyplot as plt
import numpy as np

# Define the constraints as functions
def constraint1(x1):
    return (147 - 2 * x1) / 3

def constraint2(x1):
    return (210 - 3 * x1) / 4

def constraint3(x1):
    return 63 - x1

# Define the x1 range for plotting
x1 = np.linspace(0, 100, 500)

# Calculate corresponding x2 values for each constraint
x2_1 = constraint1(x1)
x2_2 = constraint2(x1)
x2_3 = constraint3(x1)

# Set up the plot
plt.figure(figsize=(8, 8))
plt.plot(x1, x2_1, label=r'$2x_1 + 3x_2 \leq 147$')
plt.plot(x1, x2_2, label=r'$3x_1 + 4x_2 \leq 210$')
plt.plot(x1, x2_3, label=r'$x_1 + x_2 \leq 63$')

# Fill the feasible region
plt.fill_between(x1, np.minimum(np.minimum(x2_1, x2_2), x2_3), color='lightblue', alpha=0.5)

# Plot settings
plt.xlim(0, 80)
plt.ylim(0, 80)
plt.xlabel('$x_1$')
plt.ylabel('$x_2$')
plt.axhline(0, color='white',linewidth=0.5)
plt.axvline(0, color='white',linewidth=0.5)
plt.grid(True, which='both', linestyle='--', linewidth=0.5)
plt.legend()
plt.title('Graphical Representation of the Linear Programming Problem')

# Display the plot
plt.show()
