package build.wallet.di

import me.tatarka.inject.annotations.Scope
import kotlin.annotation.AnnotationRetention.RUNTIME
import kotlin.annotation.AnnotationTarget.*
import kotlin.reflect.KClass

/**
 * A scope annotation for kotlin-inject to make classes singletons in the specified [scope],
 * e.g. to make a class a singleton in the application scope you'd use:
 * ```
 * @Inject
 * @SingleIn(AppScope::class)
 * class MyClass(..) : SuperType {
 *     ...
 * }
 * ```
 *
 * For Android and JVM targets this annotation is also marked with JSR-330 annotations and
 * therefore the same annotation can be used for Dagger 2 and Anvil.
 */
@Scope
@Retention(RUNTIME)
@Target(CLASS, FUNCTION, PROPERTY_GETTER, VALUE_PARAMETER)
annotation class SingleIn(
  /**
   * The marker that identifies this scope.
   */
  val scope: KClass<*>,
)
