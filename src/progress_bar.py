class ProgressBar:
    def __init__(self, num_of_steps: int, legend: str, width: int = 40):
        self.width = width
        self.num_of_steps = num_of_steps
        self.legend = legend
        self.cur_operation_step = 0
        self.cur_progress_step = 0
        self.progress_step_size = int(self.num_of_steps / self.width)
        self.progress_state = ('#' * self.cur_progress_step) + (
                '-' * (self.width - self.cur_progress_step + 1))

    def __iter__(self):
        return self

    def __next__(self):
        self.cur_operation_step += 1
        if self.num_of_steps < self.width:
            self.cur_progress_step += 1

        elif self.cur_operation_step == (self.cur_progress_step *
                                       self.progress_step_size + 1):
            self.cur_progress_step += 1

        self.progress_state = ('#' * self.cur_progress_step) + (
            '-' * (self.width - self.cur_progress_step + 1)
        )
        current_progress = (f"{self.legend}  [{self.progress_state}]  "
                            f"{self.cur_operation_step}/{self.num_of_steps}")
        print(current_progress, end="\r")

        if self.cur_operation_step == self.num_of_steps:
            print(f"{self.legend}  [{'#' * self.width}]  "
                  f"{self.cur_operation_step}/{self.num_of_steps}")

        if self.cur_progress_step > self.width + 2:
            raise StopIteration

    def set_up_progress_bar(self):
        initial_progress = (f"{self.legend}  [{self.progress_state}]  "
                            f"{self.cur_operation_step}/{self.num_of_steps}")
        print(initial_progress, end="\r")
