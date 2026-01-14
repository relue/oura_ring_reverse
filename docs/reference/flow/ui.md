# UI Layer Data Flow

Repository pattern, ViewModel, and Compose UI.

---

## Layer 5: Repository Pattern

### Data Access Layer

```
Repository
    ├── query Realm database
    ├── transform to domain models
    └── expose as Flow<T>
```

### Example Pattern

```kotlin
class SleepRepository {
    fun getSleep(date: LocalDate): Flow<Sleep> {
        return realm.query<DbSleep>("date == $date")
            .asFlow()
            .map { it.toDomainModel() }
    }
}
```

---

## Layer 6: ViewModel Layer

ViewModels observe repositories and expose UI state.

### Pattern

```kotlin
class SleepViewModel : ViewModel() {
    val state: StateFlow<UiState> = sleepRepository
        .getSleepFlow()
        .map { sleep ->
            UiState(
                score = sleep.score,
                contributors = sleep.contributors,
                stages = sleep.stages
            )
        }
        .stateIn(viewModelScope)
}
```

---

## UI Update Flow

### Repository Emission

```kotlin
// Repository emits new data
sleepRepository.getSleep(date).collect { sleep ->
    // ViewModel updates state
    _state.value = SleepUiState(
        score = sleep.score,
        duration = formatDuration(sleep.totalSleep),
        contributors = sleep.contributors.map { it.toUi() }
    )
}
```

### Compose Observation

```kotlin
// Compose observes and recomposes
@Composable
fun SleepScreen(viewModel: SleepViewModel) {
    val state by viewModel.state.collectAsState()
    SleepScoreCard(score = state.score)
    ContributorsList(contributors = state.contributors)
}
```

---

## Main Screens

| Screen | ViewModel | Data Source |
|--------|-----------|-------------|
| Today | TodayViewModel | Sleep, Readiness, Activity repos |
| Sleep | SleepViewModel | SleepRepository |
| Readiness | ReadinessViewModel | ReadinessRepository |
| Activity | ActivityViewModel | ActivityRepository |
| Workout | WorkoutViewModel | WorkoutRepository |

---

## State Management

### UiState Pattern

```kotlin
sealed class SleepUiState {
    object Loading : SleepUiState()
    data class Success(
        val score: Int,
        val duration: String,
        val contributors: List<Contributor>
    ) : SleepUiState()
    data class Error(val message: String) : SleepUiState()
}
```

### StateFlow Exposure

```kotlin
class SleepViewModel : ViewModel() {
    private val _state = MutableStateFlow<SleepUiState>(SleepUiState.Loading)
    val state: StateFlow<SleepUiState> = _state.asStateFlow()
}
```

---

## Threading

| Layer | Thread |
|-------|--------|
| Repository queries | Realm thread |
| Flow transformations | Dispatchers.Default |
| StateFlow collection | Main |
| Compose recomposition | Main |

---

## Source References

**Decompiled Classes:**
- `com.ouraring.oura.sleep.SleepViewModel`
- `com.ouraring.oura.readiness.ReadinessViewModel`
- `com.ouraring.oura.activity.ActivityViewModel`
- `com.ouraring.core.repository.SleepRepository`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── oura/
│   ├── sleep/SleepViewModel.java
│   ├── readiness/ReadinessViewModel.java
│   └── activity/ActivityViewModel.java
└── core/repository/
    ├── SleepRepository.java
    └── ReadinessRepository.java
```

---

## See Also

- [Structures](../structures/_index.md) - Data model definitions
- [Scores](../scores/_index.md) - Score algorithms
